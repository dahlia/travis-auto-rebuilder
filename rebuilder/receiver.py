import uuid

from sqlalchemy.orm import relationship
from sqlalchemy.schema import Column, ForeignKey
from sqlalchemy.sql.functions import now
from sqlalchemy.types import Integer, Unicode
from sqlalchemy_utc import UtcDateTime
from sqlalchemy_utils.types.json import JSONType
from sqlalchemy_utils.types.scalar_list import ScalarListType
from sqlalchemy_utils.types.uuid import UUIDType

from .orm import Base

__all__ = 'Receiver', 'Restart'


class Receiver(Base):

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    repo_slug = Column(Unicode, nullable=False)
    token = Column(Unicode, nullable=False)
    created_at = Column(UtcDateTime, nullable=False, default=now())
    restarts = relationship('Restart')

    __tablename__ = 'receiver'


class Restart(Base):
    """Logs of jobs restarted."""

    id = Column(UUIDType, primary_key=True, default=uuid.uuid4)
    receiver_id = Column(UUIDType, ForeignKey(Receiver.id), nullable=False)
    receiver = relationship(Receiver)
    received_payload = Column(JSONType, nullable=False)
    build_id = Column(Integer, nullable=False, index=True)
    build_number = Column(Integer, nullable=False)
    build_finished_at = Column(UtcDateTime, nullable=False)
    failed_job_numbers = Column(ScalarListType(int), nullable=False)
    created_at = Column(UtcDateTime, nullable=False, default=now())

    __tablename__ = 'restart'
