import datetime
import re
from typing import AbstractSet, Mapping, Optional, Tuple
import urllib.request
import uuid

from flask import (Flask, current_app, g, json, jsonify, redirect,
                   render_template, request, url_for)
from iso8601 import parse_date
from sqlalchemy.engine import Engine, create_engine
from werkzeug.exceptions import BadRequest, NotFound
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
    try:
        max_retries = int(max_retries)
    except ValueError:
        raise BadRequest('Max retries must be a natural number.')
    if not (1 <= max_retries <= 5):
        raise BadRequest('Max retries must be greater than 0 and less than 6.')
    try:
        job_numbers = {
            int(n.strip())
            for n in job_numbers.split(',') if n.strip()
        }
    except ValueError:
        raise BadRequest('Every element of job numbers must be a number.')
    if any(n < 1 for n in job_numbers):
        raise BadRequest('A job number cannot be less than 1.')
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


def get_receiver_params() -> Tuple[Optional[AbstractSet[int]], int]:
    try:
        jobs = frozenset(map(int, request.args['jobs'].split()))
    except (KeyError, ValueError):
        jobs = None
    retries = request.args.get('retries', type=int, default=1)
    return jobs, max(min(retries, 5), 1)


@app.route('/<uuid:id>/')
def show_receiver(id: uuid.UUID):
    receiver: Receiver = get_receiver(id)
    jobs, retries = get_receiver_params()
    receiver_url = url_for(
        '.receive',
        id=id,
        jobs=jobs and ' '.join(map(str, sorted(jobs))),
        retries=retries,
        _external=True
    )
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
        example_code=dump(example_conf)
    )


@app.route('/<uuid:id>/', methods=['POST'])
def receive(id: uuid.UUID):
    session: Session = get_session()
    receiver: Receiver = get_receiver(id)
    job_numbers, retries = get_receiver_params()
    payload_text: str = request.form['payload']
    # FIXME: validate signature
    # https://docs.travis-ci.com/user/notifications/#Verifying-Webhook-requests
    payload = json.loads(payload_text)
    repo_slug = '{owner_name}/{name}'.format(**payload['repository'])
    if repo_slug != receiver.repo_slug:
        return jsonify(result='unmatched_repo_slug')
    jobs = payload['matrix']
    if job_numbers is not None:
        jobs = [
            job
            for job in jobs
            if int(job['number'].split('.')[-1]) in job_numbers
        ]
    failed_jobs = [j for j in jobs if j['state'] != 'passed']
    if not failed_jobs:
        return jsonify(result='jobs_passed')
    build_id = payload['id']
    prev_logs = session.query(Restart) \
        .filter_by(receiver=receiver, build_id=build_id) \
        .count()
    if prev_logs >= retries:
        return jsonify(result='too_many_retries')
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
                return jsonify(result='invalid_token')
            raise
        restarted_jobs.append(restarted_job)
    session.commit()
    # Clean up old logs
    now = datetime.datetime.now(datetime.timezone.utc)
    a_day_ago = now - datetime.timedelta(days=1)
    session.query(Restart).filter(Restart.created_at < a_day_ago).delete()
    session.commit()
    return jsonify(result='jobs_restarted', restarted_jobs=restarted_jobs)


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