from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

import settings

engine = create_engine(settings.DB)
session_factory = sessionmaker(bind=engine)
DBSession = scoped_session(session_factory)
