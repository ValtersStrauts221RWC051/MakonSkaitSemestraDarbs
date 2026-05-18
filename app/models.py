from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
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
    client_port: Mapped[int] = mapped_column(Integer, default=0)
    proto: Mapped[str] = mapped_column(String, default="udp")
    query_type: Mapped[str] = mapped_column(String, index=True)
    query_name: Mapped[str] = mapped_column(String, index=True)
    query_class: Mapped[str] = mapped_column(String, default="IN")
    parent_domain: Mapped[str] = mapped_column(String, default="", index=True)
    subdomain_depth: Mapped[int] = mapped_column(Integer, default=0)
    rcode: Mapped[str] = mapped_column(String)
    response_size: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    dns_id: Mapped[str] = mapped_column(String, default="")
    opcode: Mapped[str] = mapped_column(String, default="")
    bufsize: Mapped[str] = mapped_column(String, default="")
    do_flag: Mapped[str] = mapped_column(String, default="")
    raw_log: Mapped[dict] = mapped_column(JSONB, default=dict)

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


class DomainInfo(Base):
    __tablename__ = "domain_info"

    parent_domain: Mapped[str] = mapped_column(String, primary_key=True)
    ip: Mapped[str] = mapped_column(String, default="")
    country: Mapped[str] = mapped_column(String, default="", index=True)
    country_code: Mapped[str] = mapped_column(String, default="", index=True)
    city: Mapped[str] = mapped_column(String, default="")
    isp: Mapped[str] = mapped_column(String, default="")
    registrar: Mapped[str] = mapped_column(String, default="")
    creation_date: Mapped[str] = mapped_column(String, default="")
    whois_country: Mapped[str] = mapped_column(String, default="")
    looked_up_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    error: Mapped[str] = mapped_column(String, default="")


