"""
RegLog CSV — Server-side log-to-CSV converter.
Parses Apache, Nginx, and syslog formats and returns structured CSV.
"""

import csv
import io
import re
import os
from flask import Flask, request, jsonify, send_file, send_from_directory

app = Flask(__name__, static_folder="static", static_url_path="")

# ---------------------------------------------------------------------------
# Log format parsers
# ---------------------------------------------------------------------------

# Apache/Nginx Combined Log Format:
#   %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
# Example:
#   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/" "Mozilla/4.08"
APACHE_COMBINED_RE = re.compile(
    r'^(\S+)\s+'           # IP/host
    r'(\S+)\s+'            # ident (usually -)
    r'(\S+)\s+'            # user (usually -)
    r'\[([^\]]+)\]\s+'     # [timestamp]
    r'"([^"]*)"\s+'        # "METHOD /path HTTP/version"
    r'(\d{3})\s+'          # status code
    r'(\S+)\s+'            # size (or -)
    r'"([^"]*)"\s+'        # "referer"
    r'"([^"]*)"'           # "user-agent"
)

# Apache Common Log Format (CLF):
#   %h %l %u %t \"%r\" %>s %b
APACHE_CLF_RE = re.compile(
    r'^(\S+)\s+'
    r'(\S+)\s+'
    r'(\S+)\s+'
    r'\[([^\]]+)\]\s+'
    r'"([^"]*)"\s+'
    r'(\d{3})\s+'
    r'(\S+)'
)

# Nginx default combined (same as Apache combined, but without ident/user)
# We reuse the Apache combined regex but allow ident and user to be -
# Nginx sometimes omits ident/auth: 127.0.0.1 - - [...]
# The combined regex already handles this.

# For "request" field: "METHOD /path HTTP/version" or "METHOD /path?query HTTP/version"
REQUEST_RE = re.compile(r'^(\S+)\s+(\S+)\s*(.*)$')

# Syslog RFC 3164 (BSD syslog):
#   <PRI>timestamp hostname process[pid]: message
#   Without PRI: timestamp hostname process[pid]: message
SYSLOG_3164_RE = re.compile(
    r'^(?:<(\d{1,3})>)?'             # optional PRI
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'  # timestamp: Mmm DD HH:MM:SS
    r'(\S+)\s+'                      # hostname
    r'(\S+?)(?:\[(\d+)\])?:\s+'     # process[pid]:
    r'(.*)'                          # message
)

# Syslog RFC 5424 (IETF syslog):
#   <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MESSAGE
SYSLOG_5424_RE = re.compile(
    r'^(?:<(\d{1,3})>)?'            # optional PRI
    r'(\d+)\s+'                      # version
    r'(\S+)\s+'                      # timestamp (ISO 8601)
    r'(\S+)\s+'                      # hostname
    r'(\S+)\s+'                      # app-name
    r'(\S+)\s+'                      # procid
    r'(\S+)\s+'                      # msgid
    r'(\S+|\[[^\]]*\](?:\s+\S+=\S+)*)\s+'  # structured-data
    r'(.*)'                          # message
)

APACHE_COLUMNS = ["IP", "Ident", "User", "Timestamp", "Method", "Path", "Protocol", "Status", "Size", "Referer", "UserAgent"]
APACHE_CLF_COLUMNS = ["IP", "Ident", "User", "Timestamp", "Method", "Path", "Protocol", "Status", "Size"]
SYSLOG_3164_COLUMNS = ["Priority", "Timestamp", "Host", "Process", "PID", "Message"]
SYSLOG_5424_COLUMNS = ["Priority", "Version", "Timestamp", "Host", "AppName", "ProcID", "MsgID", "StructuredData", "Message"]

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB


def parse_request_field(request_str):
    """Split 'METHOD /path HTTP/1.1' into (method, path, protocol)."""
    m = REQUEST_RE.match(request_str.strip())
    if m:
        return m.group(1), m.group(2), m.group(3)
    return "", request_str.strip(), ""


def parse_apache_combined(lines):
    """Parse Apache/Nginx combined format lines into CSV rows."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = APACHE_COMBINED_RE.match(line)
        if m:
            method, path, protocol = parse_request_field(m.group(5))
            rows.append([
                m.group(1),   # IP
                m.group(2),   # Ident
                m.group(3),   # User
                m.group(4),   # Timestamp
                method,       # Method
                path,         # Path
                protocol,     # Protocol
                m.group(6),   # Status
                m.group(7),   # Size
                m.group(8),   # Referer
                m.group(9),   # UserAgent
            ])
    return APACHE_COLUMNS, rows


def parse_apache_clf(lines):
    """Parse Apache Common Log Format lines into CSV rows."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = APACHE_CLF_RE.match(line)
        if m:
            method, path, protocol = parse_request_field(m.group(5))
            rows.append([
                m.group(1),   # IP
                m.group(2),   # Ident
                m.group(3),   # User
                m.group(4),   # Timestamp
                method,       # Method
                path,         # Path
                protocol,     # Protocol
                m.group(6),   # Status
                m.group(7),   # Size
            ])
    return APACHE_CLF_COLUMNS, rows


def parse_nginx(lines):
    """Parse Nginx access log (alias for Apache combined)."""
    return parse_apache_combined(lines)


def parse_syslog_3164(lines):
    """Parse syslog RFC 3164 format lines into CSV rows."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_3164_RE.match(line)
        if m:
            rows.append([
                m.group(1) or "",  # Priority
                m.group(2),        # Timestamp
                m.group(3),        # Host
                m.group(4),        # Process
                m.group(5) or "",  # PID
                m.group(6),        # Message
            ])
    return SYSLOG_3164_COLUMNS, rows


def parse_syslog_5424(lines):
    """Parse syslog RFC 5424 format lines into CSV rows."""
    rows = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_5424_RE.match(line)
        if m:
            rows.append([
                m.group(1) or "",  # Priority
                m.group(2),        # Version
                m.group(3),        # Timestamp
                m.group(4),        # Host
                m.group(5),        # AppName
                m.group(6),        # ProcID
                m.group(7),        # MsgID
                m.group(8),        # StructuredData
                m.group(9),        # Message
            ])
    return SYSLOG_5424_COLUMNS, rows


PARSERS = {
    "apache_combined": ("Apache Combined", parse_apache_combined),
    "apache_clf": ("Apache CLF (Common)", parse_apache_clf),
    "nginx": ("Nginx Access Log", parse_nginx),
    "syslog_3164": ("Syslog RFC 3164", parse_syslog_3164),
    "syslog_5424": ("Syslog RFC 5424", parse_syslog_5424),
}


def generate_csv(columns, rows):
    """Generate CSV content as a string."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/convert", methods=["POST"])
def convert():
    # --- Validate uploaded file ---
    if "file" not in request.files:
        return jsonify({"error": "Nessun file caricato. Seleziona un file di log e riprova."}), 400

    file = request.files["file"]
    if file.filename == "" or file.filename is None:
        return jsonify({"error": "Nessun file selezionato. Scegli un file di log dal tuo computer."}), 400

    # Read file content
    content = file.read()
    if len(content) == 0:
        return jsonify({"error": "Il file caricato è vuoto. Carica un file di log che contenga almeno una riga."}), 400

    if len(content) > MAX_FILE_SIZE:
        return jsonify({"error": f"Il file supera il limite di {MAX_FILE_SIZE // (1024*1024)} MB. Carica un file più piccolo."}), 400

    # Decode with fallback
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except UnicodeDecodeError:
            return jsonify({"error": "Impossibile leggere il file. Il formato non è testo o la codifica non è supportata."}), 400

    lines = text.splitlines()

    # --- Validate format selection ---
    fmt = request.form.get("format", "").strip()
    if fmt not in PARSERS:
        return jsonify({"error": "Formato di log non valido. Seleziona uno dei formati supportati dall'elenco."}), 400

    parser_name, parser_fn = PARSERS[fmt]

    # --- Parse ---
    try:
        columns, rows = parser_fn(lines)
    except Exception as e:
        return jsonify({"error": f"Errore durante l'analisi del file: {str(e)}"}), 500

    if not rows:
        return jsonify({
            "error": (
                f"Nessuna riga riconosciuta come formato «{parser_name}». "
                "Verifica che il formato selezionato corrisponda al contenuto del file. "
                "Righe analizzate nel file: {}.".format(len([l for l in lines if l.strip()]))
            )
        }), 400

    # --- Generate CSV ---
    try:
        csv_content = generate_csv(columns, rows)
    except Exception as e:
        return jsonify({"error": f"Errore durante la generazione del CSV: {str(e)}"}), 500

    # --- Return as downloadable file ---
    original_name = os.path.splitext(file.filename)[0]
    csv_filename = f"{original_name}_converted.csv"

    return (
        csv_content,
        200,
        {
            "Content-Type": "text/csv; charset=utf-8",
            "Content-Disposition": f'attachment; filename="{csv_filename}"',
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 4599))
    app.run(host="0.0.0.0", port=port, debug=False)
