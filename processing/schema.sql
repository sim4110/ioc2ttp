-- project.pdf 3-3 DB 스키마 설계 그대로 반영
CREATE TABLE IF NOT EXISTS samples (
    sha256_hash VARCHAR(64) PRIMARY KEY,
    md5_hash VARCHAR(32),
    sha1_hash VARCHAR(40),
    file_name TEXT,
    file_size INTEGER,
    file_type VARCHAR(20),
    signature VARCHAR(100),
    tags TEXT[],
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    delivery_method VARCHAR(50),
    origin_country VARCHAR(10),
    code_sign TEXT,
    -- get_info() 상세조회 보강 필드 (samples 중 일부에 한해 채워짐, 3-1 Feature Extraction 확장)
    imphash VARCHAR(64),
    tlsh TEXT,
    ssdeep TEXT,
    reporter VARCHAR(50),
    vendor_family VARCHAR(150),
    vendor_score INTEGER,
    enriched_at TIMESTAMP
);

-- 기존에 samples 테이블이 이미 있던 환경(스키마 v1)을 위한 마이그레이션
ALTER TABLE samples ADD COLUMN IF NOT EXISTS imphash VARCHAR(64);
ALTER TABLE samples ADD COLUMN IF NOT EXISTS tlsh TEXT;
ALTER TABLE samples ADD COLUMN IF NOT EXISTS ssdeep TEXT;
ALTER TABLE samples ADD COLUMN IF NOT EXISTS reporter VARCHAR(50);
ALTER TABLE samples ADD COLUMN IF NOT EXISTS vendor_family VARCHAR(150);
ALTER TABLE samples ADD COLUMN IF NOT EXISTS vendor_score INTEGER;
ALTER TABLE samples ADD COLUMN IF NOT EXISTS enriched_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS yara_matches (
    id SERIAL PRIMARY KEY,
    sha256_hash VARCHAR(64) REFERENCES samples(sha256_hash),
    rule_name VARCHAR(150)
);

CREATE TABLE IF NOT EXISTS sample_behaviors (
    id SERIAL PRIMARY KEY,
    sha256_hash VARCHAR(64) REFERENCES samples(sha256_hash),
    behavior TEXT,
    score INTEGER
);

CREATE TABLE IF NOT EXISTS sample_references (
    id SERIAL PRIMARY KEY,
    sha256_hash VARCHAR(64) REFERENCES samples(sha256_hash),
    context VARCHAR(50),
    value TEXT
);

CREATE TABLE IF NOT EXISTS vulnerable_drivers (
    hash_sha256 VARCHAR(64) PRIMARY KEY,
    driver_name VARCHAR(150),
    category VARCHAR(20),
    cve_id VARCHAR(20),
    publisher VARCHAR(150),
    source VARCHAR(50) DEFAULT 'loldrivers'
);

CREATE TABLE IF NOT EXISTS attack_ttp_mapping (
    id SERIAL PRIMARY KEY,
    signature VARCHAR(100),
    software_name VARCHAR(150),
    technique_id VARCHAR(20),
    technique_name VARCHAR(150),
    tactic VARCHAR(50)
);

-- MITRE ATT&CK Group(intrusion-set)이 공식 문서화한 attack chain.
-- via_software가 비어있으면 그룹이 technique을 직접 쓰는 것으로 문서화된 것이고,
-- 값이 있으면 그 소프트웨어를 경유해서 쓰는 technique이다.
CREATE TABLE IF NOT EXISTS attack_group_technique (
    id SERIAL PRIMARY KEY,
    group_name VARCHAR(150),
    technique_id VARCHAR(20),
    technique_name VARCHAR(150),
    tactic VARCHAR(50),
    via_software VARCHAR(150)
);

-- 우리가 수집에 쓴 APT 태그(예: 'Lazarus')와 MITRE Group 정식명(예: 'Lazarus Group')의 대응.
CREATE TABLE IF NOT EXISTS group_tag_resolution (
    local_tag VARCHAR(50) PRIMARY KEY,
    mitre_group_name VARCHAR(150)
);

-- 대시보드 조회 성능을 위한 보조 인덱스
CREATE INDEX IF NOT EXISTS idx_samples_signature ON samples(signature);
CREATE INDEX IF NOT EXISTS idx_samples_first_seen ON samples(first_seen);
CREATE INDEX IF NOT EXISTS idx_samples_file_type ON samples(file_type);
CREATE INDEX IF NOT EXISTS idx_yara_matches_hash ON yara_matches(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_sample_behaviors_hash ON sample_behaviors(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_sample_references_hash ON sample_references(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_attack_ttp_signature ON attack_ttp_mapping(signature);
CREATE INDEX IF NOT EXISTS idx_attack_ttp_tactic ON attack_ttp_mapping(tactic);
CREATE INDEX IF NOT EXISTS idx_attack_group_technique_group ON attack_group_technique(group_name);
