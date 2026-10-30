import logging
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Configure SQLAlchemy engine using the specified DATABASE_URL
# Note: pool_pre_ping tests connection liveness before usage
try:
    engine = create_engine(
        settings.DATABASE_URL,
        pool_pre_ping=True,
        echo=settings.DEBUG and settings.APP_ENV == "development",
    )
except Exception as exc:
    logger.critical(
        "Failed to initialize SQLAlchemy database engine. "
        "Please ensure PostgreSQL is running and DATABASE_URL is valid in .env: %s",
        str(exc),
    )
    raise

# Session factory for handling database connections per request
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a transactional database session per request.
    
    Yields:
        Session: Active SQLAlchemy database session.
    Ensures:
        Session is cleanly closed after the request is finished.
    """
    db = SessionLocal()
    try:
        yield db
    except SQLAlchemyError as err:
        db.rollback()
        logger.error("Database transaction rollback due to error: %s", str(err))
        raise
    finally:
        db.close()
