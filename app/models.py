from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
    )
    client_ip: Mapped[str] = mapped_column(String, index=True)
    query_type: Mapped[str] = mapped_column(String)
    query_name: Mapped[str] = mapped_column(String, index=True)
    rcode: Mapped[str] = mapped_column(String)
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)

    dns_domain_name_length: Mapped[float] = mapped_column(Float, default=0.0)
    dns_subdomain_name_length: Mapped[float] = mapped_column(Float, default=0.0)
    numerical_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    character_entropy: Mapped[float] = mapped_column(Float, default=0.0)
    max_continuous_numeric_len: Mapped[float] = mapped_column(Float, default=0.0)
    max_continuous_alphabet_len: Mapped[float] = mapped_column(Float, default=0.0)
    max_continuous_consonants_len: Mapped[float] = mapped_column(Float, default=0.0)
    max_continuous_same_alphabet_len: Mapped[float] = mapped_column(Float, default=0.0)
    vowels_consonant_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    conv_freq_vowels_consonants: Mapped[float] = mapped_column(Float, default=0.0)

    score: Mapped[float] = mapped_column(Float)
    threshold: Mapped[float] = mapped_column(Float)
    alerted: Mapped[bool] = mapped_column(Boolean)


class Blocklist(Base):
    __tablename__ = "blocklist"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    query_name: Mapped[str] = mapped_column(String, unique=True, index=True)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    reason: Mapped[str] = mapped_column(String, default="")
