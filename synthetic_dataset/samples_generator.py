"""
make_samples_from_templates.py  (v3)
─────────────────────────────────────────────────────────────────────
• читает templates.json
• для каждого шаблона (фильтр unsupported + len≤200)
  генерирует T примеров на LANGS
• размечает только приоритетные плейсхолдеры
• неизвестные плейсхолдеры сохраняет в unknown_placeholders.txt
"""

import json, pathlib, random, uuid, re, sys, signal
from datetime import datetime, date
from collections import defaultdict
from faker import Faker

# ─────────── ПАРАМЕТРЫ ───────────
T               = 3
TEMPLATE_FILE   = "templates_4.json"
LANGS           = ["ru_RU", "en_US"]
OUTPUT_BASE     = "samples.json"
UNKNOWN_TXT     = "unknown_placeholders.txt"

# ─────────── ПРИОРИТЕТНЫЕ PII ───────────
PRIORITY_PH = ["phone","fio","email","login","password","ip","ipv6","address","org"]

# ─────────── ГЛОБАЛЬНЫЙ СЕТ НЕИЗВ. ПЛЕЙСХОЛДЕРОВ ───────────
UNKNOWN_PLACEHOLDERS = set()

# ───────────  GENERATORS  ───────────
from datetime import datetime, date
import random, uuid
from decimal import Decimal      # иногда полезно для amount / cost
from faker import Faker

def build_generators(fake: Faker):
    return {
        # ───────────── СЕТЬ ─────────────
        'ip':            lambda: fake.ipv4(),
        'ipv6':          lambda: fake.ipv6(),
        'port':          lambda: random.randint(1, 65535),
        'client_ip':     lambda: fake.ipv4(),
        'server_ip':     lambda: fake.ipv4(),
        'nip':           lambda: fake.ipv4(),
        'client_port':   lambda: random.randint(1, 65535),
        'server_port':   lambda: random.randint(1, 65535),
        'domain':        lambda: fake.domain_name(),
        'hostname':      lambda: fake.hostname(),
        'edge_location': lambda: fake.city_suffix(),
        'region': lambda: (
                fake.state_abbr()                           # en_US, en_GB …
                if callable(getattr(fake, "state_abbr", None))
                else fake.state()                           # ru_RU, fr_FR …
                if callable(getattr(fake, "state", None))
                else fake.country_code()                    # последний резерв
        ),

        # ───────────── URL / PATH ─────────────
        'url':           lambda: fake.url(),
        'path':          lambda: fake.uri_path(),
        'path\\':        lambda: fake.uri_path(),
        'request':       lambda: fake.uri(),

        # ───────────── ПОЛЬЗОВАТЕЛЬ / СЕССИЯ ─────────────
        'user':          lambda: fake.user_name(),
        'name':          lambda: fake.name(),
        'login':         lambda: fake.user_name(),
        'login\\':       lambda: fake.user_name(),
        'fio':           lambda: fake.name(),
        'email':         lambda: f"{fake.user_name()}@{fake.free_email_domain()}",
        'phone':         lambda: fake.phone_number(),
        'uuid':          lambda: str(uuid.uuid4()),
        'cid':           lambda: str(uuid.uuid4()),
        'uid':           lambda: random.randint(10000, 99999),
        'sessionid':     lambda: str(uuid.uuid4()),
        'deviceid':      lambda: fake.sha1()[:16],
        'user_data':     lambda: fake.sentence(nb_words=6),

        # ───────────── ВРЕМЯ ─────────────
        'ts':            lambda: datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
        'ts\\':          lambda: datetime.now().strftime('%d/%b/%Y:%H:%M:%S %z'),
        'iso_ts':        lambda: datetime.now().isoformat(),
        '@t':            lambda: datetime.now().isoformat(),
        'date':          lambda: date.today().isoformat(),
        'time':          lambda: datetime.now().strftime('%H:%M:%S'),
        'timems':        lambda: random.randint(0, 9_999),
        'timestamp':     lambda: int(datetime.now().timestamp()),
        'timezone':      lambda: fake.timezone(),
        'tz':            lambda: datetime.now().astimezone().tzname() or 'UTC',

        # ───────────── HTTP ─────────────
        'method':        lambda: random.choice(['GET','POST','PUT','DELETE','PATCH','OPTIONS']),
        'method\\':      lambda: random.choice(['GET','POST','PUT','DELETE','PATCH','OPTIONS']),
        'get':           lambda: 'GET',
        'proto':         lambda: random.choice(['HTTP/1.0','HTTP/1.1','HTTP/2']),
        'status':        lambda: random.choice([200,201,204,301,302,400,401,403,404,500,502,503]),
        'status\\':      lambda: random.choice([200,201,404,500]),
        'bytes':         lambda: random.randint(0, 1_000_000),
        'bytes\\':       lambda: random.randint(0, 1_000_000),
        'cc_bytes':      lambda: random.randint(0, 1_000_000),
        'sc_bytes':      lambda: random.randint(0, 1_000_000),
        'ref':           lambda: fake.uri(),
        'ua':            lambda: fake.user_agent(),
        'ua\\':          lambda: fake.user_agent(),

        # ───────────── ПРОЦЕССЫ / ПОТОКИ ─────────────
        'pid':           lambda: random.randint(100, 5000),
        'pid\\':         lambda: random.randint(100, 5000),
        'tid':           lambda: random.randint(1000, 10000),
        'tid\\':         lambda: random.randint(1000, 10000),
        'thread':        lambda: random.randint(1, 500),
        'thread_id':     lambda: random.randint(1, 500),
        'threadid':      lambda: random.randint(1, 500),
        'tty':           lambda: f"pts/{random.randint(0, 5)}",

        # ───────────── ЛОГИРОВАНИЕ / БД ─────────────
        'level':         lambda: random.choice(['DEBUG','INFO','WARN','ERROR','CRITICAL']),
        'db':            lambda: fake.word(),
        'sql':           lambda: fake.sentence(nb_words=6),
        'proc':          lambda: fake.word(),
        'process_name':  lambda: fake.word(),
        'program':       lambda: fake.word(),
        'interface':     lambda: random.choice(['eth0','eth1','lo','wlan0']),
        'log':           lambda: fake.sentence(nb_words=8),
        'msg':           lambda: fake.sentence(nb_words=8),
        'message':       lambda: fake.sentence(nb_words=8),
        'error':         lambda: fake.word(),
        'exception':     lambda: fake.word(),
        'syslog_rfc5424':lambda: datetime.utcnow().isoformat() + "Z",

        # ───────────── ФИНАНСЫ / МЕТРИКИ ─────────────
        'amount':        lambda: str(round(random.uniform(10, 1000), 2)),
        'currency':      lambda: random.choice(['USD','EUR','RUB','GBP','CNY']),
        'cost':          lambda: str(round(random.uniform(0.1, 50), 2)),
        'policy_number': lambda: f"POL-{random.randint(100000,999999)}",

        # ───────────── РАЗНОЕ ─────────────
        'command':       lambda: random.choice(['SELECT','INSERT','UPDATE','DELETE']),
        'args':          lambda: fake.sentence(nb_words=4),
        'event':         lambda: fake.word(),
        'caller':        lambda: fake.user_name(),
        'fid':           lambda: str(uuid.uuid4()),
        'version':       lambda: random.choice(['1.0','1.1','2.0','2024.3']),
        'subject':       lambda: fake.sentence(nb_words=3),
        'request_time':  lambda: random.randint(1, 5000),
        'response_time': lambda: random.randint(1, 5000),
        'total_time':    lambda: random.randint(1, 5000),
        'bytes_read':    lambda: random.randint(0, 1_000_000),
        'queue_time':    lambda: random.randint(0, 5000),
        'connect_time':  lambda: random.randint(0, 5000),
        'app_cookies':   lambda: fake.md5(),
        'quic_bbr':      lambda: random.choice(['on','off']),
        '150ms':         lambda: f"{random.randint(1,999)}ms",
        '"@t"':            lambda: datetime.utcnow().isoformat() + "Z",
        '\"caller\"':        lambda: f"{fake.file_name()}:{random.randint(10,300)}",
        '\"event\"':         lambda: fake.word(),
        '\"level\"':         lambda: random.choice(['DEBUG','INFO','WARN','ERROR','CRITICAL']),
        '\"log\"':           lambda: fake.sentence(nb_words=8),
        '\"maskTemplate\"':  lambda: "{ip}-{user}",
        '\"message\"':       lambda: fake.sentence(nb_words=6),
        '\"method\"':        lambda: random.choice(['GET','POST','PUT','DELETE','PATCH','OPTIONS']),
        '\"msg\"':           lambda: fake.sentence(nb_words=4),
        '\"user\"':          lambda: fake.user_name(),

        # ——— обычные имена без кавычек ———
        'address':         lambda: fake.address().replace("\n", ", "),
        'bucket_name':     lambda: f"{fake.word()}-{fake.word()}-{fake.country_code().lower()}",
        'client':          lambda: fake.word(),
        'host':            lambda: fake.hostname(),
        'ip\\':            lambda: fake.ipv4(),
        'ipv6\\':          lambda: fake.ipv6(),
        'ms':              lambda: random.randint(0, 5000),
        'org':             lambda: fake.company(),
        'password':        lambda: fake.password(length=10),
        'user_data':       lambda: fake.pydict(nb_elements=2),
    }


# известные плейсхолдеры (для проверки)
KNOWN_PLACEHOLDERS = set(build_generators(Faker()).keys()) | {"log_type"}

# ─────────── LABEL MAP (только приоритетные) ───────────
PLACEHOLDER_TO_LABEL = {p: p for p in PRIORITY_PH}

# ─────────── АННОТАЦИЯ ───────────
import string
import re

CLEAN_RE = re.compile(r'\\([{}"])')          # помогает убрать \{ \} \"

class SafeDict(dict):
    """Возвращает оригинальный плейсхолдер, если ключа нет в mapping"""
    def __missing__(self, key):
        UNKNOWN_PLACEHOLDERS.add(key)
        return f"{{{key}}}"

def _clean_template(raw: str) -> str:
    """
    1. \{ts\} -> {ts}
    2. \} и \" убираем экранирование
    """
    return CLEAN_RE.sub(r'\1', raw)



PLACE_RE = re.compile(r'{([^{}]+)}')         # вытаскиваем всё, что в фигурных скобках

def generate_and_annotate(template: str, fake: Faker, log_type: str):
    # --- 1. «Разэкранируем» шаблон
    template = _clean_template(template)

    # --- 2. собираем замены
    gens = build_generators(fake)
    mapping = {k: g() for k, g in gens.items() if f'{{{k}}}' in template}

    if "{log_type}" in template:
        mapping["log_type"] = log_type

    # --- 3. безопасное format
    try:
        text = string.Formatter().vformat(template, (), SafeDict(mapping))
    except Exception as e:
        # нельзя сформировать строку (невалидные скобки и т.п.)
        print(f"[SKIP] template '{template[:60]}…' → {e}")
        return None


    # --- 4. аннотируем ТОЛЬКО приоритетные
    spans = []
    for key in PRIORITY_PH:
        val = mapping.get(key)
        if val is None:
            continue
        v, pos = str(val), 0
        while True:
            idx = text.find(v, pos)
            if idx == -1:
                break
            spans.append({
                "label": key,
                "start": idx + 1,
                "end": idx + len(v) + 1,
                "value": v
            })
            pos = idx + len(v)
    spans.sort(key=lambda x: x["start"])

    # --- 5. фиксируем неизвестные (после чистки)
    for ph_raw in PLACE_RE.findall(template):
        ph = ph_raw.replace("\\", "").replace('"', '')
        if ph not in KNOWN_PLACEHOLDERS:
            UNKNOWN_PLACEHOLDERS.add(ph)

    return {"text": text, "spans": spans}



# ─────────── FILE HELPERS ───────────
def next_free_filename(base: str) -> str:
    p = pathlib.Path(base)
    if not p.exists():
        return str(p)
    stem, suf = p.stem, p.suffix
    i = 1
    while True:
        name = f"{stem}_{i}{suf}"
        if not pathlib.Path(name).exists():
            return name
        i += 1

def save_unknown():
    if not UNKNOWN_PLACEHOLDERS:
        return
    fname = next_free_filename(UNKNOWN_TXT)
    with open(fname, "w", encoding="utf-8") as fp:
        fp.write("\n".join(sorted(UNKNOWN_PLACEHOLDERS)))
    print(f"⚠ Unknown placeholders saved to {fname}")

def sigint_handler(sig, frame):
    print("\n[INTERRUPT] stopping, saving unknown placeholders…")
    save_unknown()
    sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)

# ─────────── MAIN ───────────
def main():
    try:
        templates = json.load(open(TEMPLATE_FILE, encoding="utf-8"))
        out = defaultdict(lambda: defaultdict(dict))
        fakers = {lang: Faker(lang) for lang in LANGS}

        for log_type, buckets in templates.items():
            for bucket, tmpl_list in buckets.items():
                for template in tmpl_list:

                    # --- фильтры unsupported + длина -------------
                    if "unsupported" in template.lower():
                        continue
                    if len(template) > 200:
                        continue

                    # --- поиск неизвестных плейсхолдеров ---------
                    for ph in re.findall(r"{(\w+)}", template):
                        if ph not in KNOWN_PLACEHOLDERS:
                            UNKNOWN_PLACEHOLDERS.add(ph)

                    for lang, fk in fakers.items():
                        samples = []
                        for _ in range(T):
                            sample = generate_and_annotate(template, fk, log_type)
                            if sample is None:              #  ←  шаблон не обработан
                                samples = None
                                break
                            samples.append(sample)

                        if samples:                         #  только если всё успешно
                            out[log_type][bucket].setdefault(template, {})[lang] = samples


        out_file = next_free_filename(OUTPUT_BASE)
        json.dump(out, open(out_file, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print(f"✔ {out_file} created ({T} samples × {len(LANGS)} languages)")

    finally:
        # сохранение неизвестных плейсхолдеров даже при исключении
        save_unknown()


if __name__ == "__main__":
    main()