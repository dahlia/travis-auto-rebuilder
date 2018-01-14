from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

__all__ = 'Base', 'Session'


Base = declarative_base()
Session = sessionmaker()
