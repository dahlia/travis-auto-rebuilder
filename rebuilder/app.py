import base64
import datetime
import os
import re
from typing import AbstractSet, Mapping, Optional, Tuple
import urllib.request
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import (Flask, current_app, g, json, jsonify, redirect,
                   render_template, request, url_for)
from iso8601 import parse_date
from sqlalchemy.engine import Engine, create_engine
from werkzeug.exceptions import BadRequest, NotFound
from werkzeug.wrappers import BaseResponse
from yaml import dump

from .orm import Base, Session
from .receiver import Receiver, Restart


app = Flask(__name__)


@app.before_first_request
def initialize_database():
    Base.metadata.create_all(get_engine())


def get_engine() -> Engine:
    if not hasattr(g, 'engine'):
        g.engine = create_engine(current_app.config['DATABASE_URL'])
    return g.engine


def get_session() -> Session:
    if not hasattr(request, 'orm_session'):
        request.orm_session = Session(bind=get_engine())
    return request.orm_session


@app.teardown_request
def close_session(*args):
    if hasattr(request, 'orm_session'):
        request.orm_session.close()
        del request.orm_session


@app.route('/')
def home():
    return render_template('home.html')


def parse_job_numbers(string: str, label: str):
    try:
        job_numbers = {int(n.strip()) for n in string.split(',') if n.strip()}
    except ValueError:
        raise BadRequest(
            f'The {label} field: '
            'Every element of job numbers must be a number.'
        )
    if any(n < 1 for n in job_numbers):
        raise BadRequest(
            f'The {label} field: A job number cannot be less than 1.'
        )
    return job_numbers


@app.route('/', methods=['POST'])
def create_receiver():
    def get(d, key: str) -> str:
        v = d[key].strip()
        if not v:
            raise KeyError(key)
        return v
    try:
        repo_slug = get(request.form, 'repo-slug')
        token = get(request.form, 'token')
        max_retries = get(request.form, 'max-retries')
    except KeyError as e:
        raise BadRequest(
            f'Missing required field: {e.args[0].replace("-", " ")}.'
        )
    job_numbers = request.form.get('job-numbers', '').strip()
    subject_to = request.form.get('subject-to', '').strip()
    try:
        max_retries = int(max_retries)
    except ValueError:
        raise BadRequest('Max retries must be a natural number.')
    if not (1 <= max_retries <= 5):
        raise BadRequest('Max retries must be greater than 0 and less than 6.')
    job_numbers = parse_job_numbers(job_numbers, 'job numbers')
    subject_to = parse_job_numbers(subject_to, 'subject to')
    if job_numbers & subject_to:
        raise BadRequest(
            'The jobs specified by "job numbers" field and "subject to" field '
            'cannot be overlapped.'
        )
    session: Session = get_session()
    receiver = Receiver(repo_slug=repo_slug, token=token)
    session.add(receiver)
    session.commit()
    jobs = ' '.join(map(str, sorted(job_numbers))) if job_numbers else None
    return redirect(
        url_for(
            '.show_receiver',
            id=receiver.id,
            jobs=jobs,
            retries=max_retries
        )
    )


def get_receiver(id: uuid.UUID) -> Receiver:
    session: Session = get_session()
    receiver: Optional[Receiver] = session.query(Receiver).get(id)
    if receiver is None:
        raise NotFound()
    return receiver


def get_receiver_params() -> Tuple[
    Optional[AbstractSet[int]],
    Optional[AbstractSet[int]],
    int
]:
    try:
        jobs = frozenset(map(int, request.args['jobs'].split()))
    except (KeyError, ValueError):
        jobs = None
    try:
        subject_to = frozenset(map(int, request.args['subject-to'].split()))
    except (KeyError, ValueError):
        subject_to = frozenset()
    retries = request.args.get('retries', type=int, default=1)
    return jobs - subject_to or None, subject_to, max(min(retries, 5), 1)


@app.route('/<uuid:id>/')
def show_receiver(id: uuid.UUID):
    receiver: Receiver = get_receiver(id)
    jobs, subject_to, retries = get_receiver_params()
    receiver_url = url_for('.receive', _external=True, **{
        'id': id,
        'jobs': jobs and ' '.join(map(str, sorted(jobs))),
        'subject-to':
            ' '.join(map(str, sorted(subject_to))) if subject_to else None,
        'retries': retries,
    })
    example_conf = {
        'notifications': {
            'webhooks': {
                'urls': [receiver_url],
                'on_failure': 'always',
                'on_success': 'never',
                'on_start': 'never',
            },
        },
    }
    return render_template(
        'receiver.html',
        receiver_url=receiver_url,
        receiver=receiver,
        example_code=dump(example_conf),
        logs=sorted(
            receiver.restarts,
            key=lambda log: log.created_at,
            reverse=True
        )
    )


@app.route('/<uuid:id>/', methods=['POST'])
def receive(id: uuid.UUID):
    def respond(result: str, code: int=200, **kwargs) -> BaseResponse:
        r = jsonify(result=result, **kwargs)
        r.status_code = code
        return r
    session: Session = get_session()
    receiver: Receiver = get_receiver(id)
    job_numbers, subject_to, retries = get_receiver_params()
    payload_text: str = request.form['payload']
    public_key: bytes = get_travis_public_key()
    try:
        signature = base64.b64decode(request.headers['Signature'])
    except KeyError:
        return respond('missing_signature', 400)
    except (ValueError, TypeError):
        return respond('invalid_signature', 400)
    if not verify_signature(payload_text.encode('utf-8'),
                            signature,
                            public_key):
        return respond('signature_verification_failure', 400)
    payload = json.loads(payload_text)
    repo_slug = '{owner_name}/{name}'.format(**payload['repository'])
    if repo_slug != receiver.repo_slug:
        return respond('unmatched_repo_slug', 400)
    all_jobs = payload['matrix']
    if job_numbers is None:
        jobs = list(all_jobs)
    else:
        jobs = [
            job
            for job in all_jobs
            if int(job['number'].split('.')[-1]) in job_numbers
        ]
    failed_jobs = [j for j in jobs if j['state'] != 'passed']
    if not failed_jobs:
        return respond('jobs_passed')
    elif (subject_to is not None and
          not all(j['state'] == 'passed' for j in subject_to)):
        return respond('jobs_failed')
    build_id = payload['id']
    prev_logs = session.query(Restart) \
        .filter_by(receiver=receiver, build_id=build_id) \
        .count()
    if prev_logs >= retries:
        return respond('too_many_retries', 429)
    log = Restart(
        receiver=receiver,
        received_payload=payload,
        build_id=build_id,
        build_number=int(payload['number']),
        build_finished_at=parse_date(payload['finished_at']),
        failed_job_numbers=[
            int(job['number'].split('.')[-1])
            for job in failed_jobs
        ]
    )
    request_id = request.headers.get('X-Request-ID', '')
    if re.match(r'^[0-9a-fA-F]{32}$', request_id):
        log.id = uuid.UUID(request_id)
    session.add(log)
    session.flush()
    restarted_jobs = []
    for job in failed_jobs:
        try:
            restarted_job = restart_job(job['id'], receiver.token)
        except urllib.error.HTTPError as e:
            session.rollback()
            if e.code == 403:
                return respond('invalid_token', 403)
            raise
        restarted_jobs.append(restarted_job)
    session.commit()
    # Clean up old logs
    now = datetime.datetime.now(datetime.timezone.utc)
    a_day_ago = now - datetime.timedelta(days=1)
    session.query(Restart).filter(Restart.created_at < a_day_ago).delete()
    session.commit()
    return respond('jobs_restarted', restarted_jobs=restarted_jobs, code=202)


SIGNING_HASH_ALGORITHM = SHA1()
SIGNING_PADDING = PKCS1v15()


def verify_signature(payload: bytes,
                     signature: bytes,
                     public_key_pem: bytes) -> bool:
    pubkey = load_pem_public_key(public_key_pem, backend=default_backend())
    try:
        pubkey.verify(
            signature,
            payload,
            SIGNING_PADDING,
            SIGNING_HASH_ALGORITHM
        )
    except InvalidSignature:
        current_app.logger.info('verify_signature(%r, %r, %r) failed.',
                                payload, signature, public_key_pem)
        return False
    return True


def get_travis_public_key():
    if not hasattr(g, 'travis_public_key'):
        with urllib.request.urlopen('https://api.travis-ci.org/config') as r:
            config = json.load(r)
        pem = config['config']['notifications']['webhook']['public_key']
        g.travis_public_key = pem.encode('ascii')
    return g.travis_public_key


def restart_job(job_id: int, token: str) -> Mapping[str, object]:
    request = urllib.request.Request(
        f'https://api.travis-ci.org/job/{job_id}/restart',
        method='POST',
        headers={
            'Travis-API-Version': '3',
            'Authorization': f'token {token}',
        }
    )
    with urllib.request.urlopen(request) as response:
        assert response.headers['Content-Type'].strip() == 'application/json'
        return json.load(response)


if os.environ.get('REBUILDER_DATABASE_URL'):
    app.config.setdefault(
        'DATABASE_URL',
        os.environ['REBUILDER_DATABASE_URL'].strip()
    )
