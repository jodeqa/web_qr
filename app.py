from flask import Flask, render_template, request, jsonify, make_response
import qrcode
from qrcode.constants import ERROR_CORRECT_L, ERROR_CORRECT_M, ERROR_CORRECT_Q, ERROR_CORRECT_H
from PIL import Image
import io
import base64
import json
import datetime
import os

# On Development
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes

# On Production
# from Crypto.Cipher import AES
# from Crypto.Protocol.KDF import PBKDF2
# from Crypto.Random import get_random_bytes

import urllib.parse
import html as html_escape_module


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # limit file uploads to 2MB

# Byte‐mode capacity table (versions 1–40)
CAPACITY_TABLE = {
    1:  { 'L': 17,   'M': 14,   'Q': 11,   'H': 7 },
    2:  { 'L': 32,   'M': 26,   'Q': 20,   'H': 14 },
    3:  { 'L': 53,   'M': 42,   'Q': 32,   'H': 24 },
    4:  { 'L': 78,   'M': 62,   'Q': 46,   'H': 34 },
    5:  { 'L': 106,  'M': 84,   'Q': 60,   'H': 44 },
    6:  { 'L': 134,  'M': 106,  'Q': 74,   'H': 58 },
    7:  { 'L': 154,  'M': 122,  'Q': 86,   'H': 64 },
    8:  { 'L': 192,  'M': 152,  'Q': 108,  'H': 84 },
    9:  { 'L': 230,  'M': 180,  'Q': 130,  'H': 98 },
    10: { 'L': 271,  'M': 213,  'Q': 151,  'H': 119},
    11: { 'L': 321,  'M': 251,  'Q': 177,  'H': 137},
    12: { 'L': 367,  'M': 287,  'Q': 203,  'H': 155},
    13: { 'L': 425,  'M': 331,  'Q': 241,  'H': 177},
    14: { 'L': 458,  'M': 362,  'Q': 258,  'H': 194},
    15: { 'L': 520,  'M': 412,  'Q': 292,  'H': 220},
    16: { 'L': 586,  'M': 450,  'Q': 322,  'H': 250},
    17: { 'L': 644,  'M': 504,  'Q': 364,  'H': 280},
    18: { 'L': 718,  'M': 560,  'Q': 394,  'H': 310},
    19: { 'L': 792,  'M': 624,  'Q': 442,  'H': 338},
    20: { 'L': 858,  'M': 666,  'Q': 482,  'H': 382},
    21: { 'L': 929,  'M': 711,  'Q': 509,  'H': 403},
    22: { 'L': 1003, 'M': 779,  'Q': 565,  'H': 439},
    23: { 'L': 1091, 'M': 857,  'Q': 611,  'H': 461},
    24: { 'L': 1171, 'M': 911,  'Q': 661,  'H': 511},
    25: { 'L': 1273, 'M': 997,  'Q': 715,  'H': 535},
    26: { 'L': 1367, 'M': 1059, 'Q': 751,  'H': 593},
    27: { 'L': 1465, 'M': 1125, 'Q': 805,  'H': 625},
    28: { 'L': 1528, 'M': 1190, 'Q': 868,  'H': 658},
    29: { 'L': 1628, 'M': 1264, 'Q': 908,  'H': 698},
    30: { 'L': 1732, 'M': 1370, 'Q': 982,  'H': 742},
    31: { 'L': 1840, 'M': 1452, 'Q': 1030, 'H': 790},
    32: { 'L': 1952, 'M': 1538, 'Q': 1112, 'H': 842},
    33: { 'L': 2068, 'M': 1628, 'Q': 1168, 'H': 898},
    34: { 'L': 2188, 'M': 1722, 'Q': 1228, 'H': 958},
    35: { 'L': 2303, 'M': 1809, 'Q': 1283, 'H': 983},
    36: { 'L': 2431, 'M': 1911, 'Q': 1351, 'H': 1051},
    37: { 'L': 2563, 'M': 1989, 'Q': 1423, 'H': 1093},
    38: { 'L': 2699, 'M': 2099, 'Q': 1499, 'H': 1139},
    39: { 'L': 2809, 'M': 2213, 'Q': 1579, 'H': 1219},
    40: { 'L': 2953, 'M': 2331, 'Q': 1663, 'H': 1273},
}

ECC_MAP = {
    'L': ERROR_CORRECT_L,
    'M': ERROR_CORRECT_M,
    'Q': ERROR_CORRECT_Q,
    'H': ERROR_CORRECT_H,
}


def generate_qr_img(payload: str, version: int, ecc: str, color: str, logo_file=None):
    if color == 'Black':
        fill_color, back_color, transparent_target = 'black', 'white', (255, 255, 255)
    else:
        fill_color, back_color, transparent_target = 'white', 'black', (0, 0, 0)

    qr = qrcode.QRCode(
        version=version,
        error_correction=ECC_MAP[ecc],
        box_size=10,
        border=4
    )
    qr.add_data(payload)
    qr.make(fit=False)
    qr_img = qr.make_image(fill_color=fill_color, back_color=back_color).convert('RGBA')

    pixels = qr_img.load()
    w, h = qr_img.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = pixels[x, y]
            if (r, g, b) == transparent_target:
                pixels[x, y] = (r, g, b, 0)

    # Embed logo if provided
    if logo_file:
        try:
            logo = Image.open(logo_file).convert('RGBA')
            logo_size = int(w * 0.2)
            logo.thumbnail((logo_size, logo_size), Image.Resampling.LANCZOS)
            x_off, y_off = (w - logo_size)//2, (h - logo_size)//2
            qr_img.paste(logo, (x_off, y_off), mask=logo)
        except:
            pass

    return qr_img


@app.route('/')
def index():
    versions = list(range(1, 41))
    ecc_choices = ['L', 'M', 'Q', 'H']
    color_choices = ['Black', 'White']
    blood_types = ['A+', 'A-', 'B+', 'B-', 'O+', 'O-', 'AB+', 'AB-']

    return render_template(
        'index.html',
        versions=versions,
        ecc_choices=ecc_choices,
        color_choices=color_choices,
        blood_types=blood_types
    )


@app.route('/capacity')
def capacity():
    try:
        version = int(request.args.get('version', 1))
        ecc = request.args.get('ecc', 'L')
        if version < 1 or version > 40 or ecc not in ECC_MAP:
            raise ValueError
    except:
        return jsonify({'error': 'Invalid version or ECC'}), 400

    modules = 21 + 4 * (version - 1)
    return jsonify({
        'modules': modules,
        'dimension_mm': modules,
        'max_chars': CAPACITY_TABLE[version][ecc]
    })


@app.route('/generate', methods=['POST'])
def generate():
    mode = request.form.get('mode', 'free_text')  # 'free_text', 'emergency', 'structured', 'secure'
    version = int(request.form.get('version'))
    ecc = request.form.get('ecc')
    color = request.form.get('color', 'Black')
    logo_file = request.files.get('logo') if 'logo' in request.files else None
    action = request.form.get('action', 'generate_qr')

    if mode == 'structured':
        # Extract each field, but guard against empty name (no IndexError)
        name = request.form.get('sv_name', '').strip()
        phone = request.form.get('sv_phone', '').strip()
        address = request.form.get('sv_address', '').strip()
        email = request.form.get('sv_email', '').strip()
        blood = request.form.get('sv_blood', '')
        allergies = request.form.get('sv_allergies', '').strip()
        meds = request.form.get('sv_medications', '').strip()
        conditions = request.form.get('sv_conditions', '').strip()
        doctor = request.form.get('sv_doctor', '').strip()
        doctor_phone = request.form.get('sv_doctor_phone', '').strip()
        timestamp = datetime.datetime.now().isoformat()

        # If name is blank, split() would be empty; avoid IndexError:
        if name == '':
            fn_field = ''
            n_field = ';;;;'  # vCard "N:" with empty fields
        else:
            fn_field = name
            parts = name.split()
            last = parts[-1]
            firsts = parts[:-1]
            n_field = f"{last};{' '.join(firsts)};;;"

        vcard_lines = [
            'BEGIN:VCARD',
            'VERSION:3.0',
            f'FN:{fn_field}',
            f'N:{n_field}',
            f'TEL;TYPE=cell:{phone}',
            f'ADR;TYPE=home:;;{address.replace(",", "\\,")}',
            f'EMAIL:{email}',
            f'X-BLOOD-TYPE:{blood}',
            f'X-ALLERGIES:{allergies}',
            f'X-MEDICATIONS:{meds}',
            f'X-CHRONIC-COND:{conditions}',
            f'X-PRIMARY-DOCTOR:{doctor}',
            f'X-DOCTOR-PHONE:{doctor_phone}',
            f'X-LAST-UPDATED:{timestamp}',
            'END:VCARD'
        ]
        vcard_text = '\n'.join(vcard_lines)

        metadata_obj = {
            'last_updated': timestamp,
            'version': version,
            'ecc': ecc
        }
        metadata_text = json.dumps(metadata_obj)

        qr1 = generate_qr_img(vcard_text, version, ecc, color, logo_file)
        qr2 = generate_qr_img(metadata_text, version, ecc, color, None)

        def img_to_b64(img):
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            return base64.b64encode(buf.getvalue()).decode('utf-8')

        b64_vcard = img_to_b64(qr1)
        b64_meta = img_to_b64(qr2)
        return render_template(
                                'result.html',
                                structured=True,
                                qr_vcard=b64_vcard,
                                qr_meta=b64_meta,
                                color=color,
                                version=version
                                )
    elif mode == 'secure':
        secure_name = request.form.get('sc_name', '').strip()
        secure_data = {
            'name': secure_name,
            'address': request.form.get('sc_address', '').strip(),
            'emergency_contact': {
                'name': request.form.get('sc_ec_name', '').strip(),
                'phone': request.form.get('sc_ec_phone', '').strip()
            },
            'medical_info': request.form.get('sc_medical', '').strip(),
            'blood_type': request.form.get('sc_blood', '')
        }
        pin = request.form.get('sc_pin', '')

        salt = b"healthSalt123"
        key = PBKDF2(pin, salt, dkLen=32, count=100000)
        iv = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(secure_data).encode('utf-8'))

        encrypted_obj = {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'cipher': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8')
        }

        rendered_html = render_template(
            'secure_data_template.html',
            encrypted=json.dumps(encrypted_obj)
        )
        html_bytes = rendered_html.encode('utf-8')
        resp = make_response(html_bytes)
        resp.headers.set('Content-Type', 'text/html')
        resp.headers.set(
            'Content-Disposition',
            'attachment',
            filename='secure_data.html'
        )
        return resp

    else:
        # Free‐Text or Emergency
        raw_text = ''
        if mode == 'free_text':
            raw_text = request.form.get('text', '')
        else:  # mode == 'emergency'
            # Here, we KNOW the JS is creating a hidden field called 'text' containing exactly this JSON.
            # Since we just appended that in index.html, we can do:
            raw_text = request.form.get('text', '')
            # If 'text' were somehow missing, we'll return an empty JSON object:
            if raw_text == '':
                raw_text = json.dumps({
                    'name': '',
                    'address': '',
                    'family': {'name': '', 'phone': ''},
                    'blood_type': '',
                    'health_history': ''
                })

        if action == 'generate_html_qr':
            # 1) Wrap raw_text in an HTML page (inside <pre>) and percent-encode it
            escaped = html_escape_module.escape(raw_text)
            html_page = (
                "<!DOCTYPE html>"
                "<html lang='en'><head><meta charset='utf-8'><title>QR Data</title></head>"
                "<body style='font-family:sans-serif; padding:20px;'>"
                "<pre style='white-space:pre-wrap; word-wrap:break-word;'>"
                f"{escaped}"
                "</pre>"
                "</body></html>"
            )
            data_uri = "data:text/html;charset=utf-8," + urllib.parse.quote(html_page)
            payload = data_uri

            # 2) Find smallest version 1–40 whose capacity ≥ len(payload_bytes)
            payload_len = len(payload.encode('utf-8'))
            chosen_version = None
            for v in range(1, 41):
                if CAPACITY_TABLE[v][ecc] >= payload_len:
                    chosen_version = v
                    break

            if chosen_version is None:
                # Too large for any QR version
                return ("<h3>Error:</h3>"
                        "<p>"
                        "Your HTML‐wrapped content is too large for any QR version (even Version 40).<br>"
                        "Try shortening the text or use “Generate QR” instead of “Generate HTML QR.”"
                        "</p>"), 400

            # Override version with chosen_version
            version = chosen_version

        else:
            # Plain QR (no HTML wrapping): use raw_text
            payload = raw_text
            # Check capacity of raw_text itself for whichever version the user selected
            if len(raw_text.encode('utf-8')) > CAPACITY_TABLE[version][ecc]:
                return f"<h3>Error: data exceeds capacity for Version {version} ECC {ecc}.</h3>", 400

        # Capacity check
        if action != 'generate_html_qr':
            if len(raw_text.encode('utf-8')) > CAPACITY_TABLE[version][ecc]:
                return f"<h3>Error: data exceeds capacity for Version {version} ECC {ecc}.</h3>", 400

            qr_img = generate_qr_img(raw_text, version, ecc, color, logo_file)
            buf = io.BytesIO()
            qr_img.save(buf, format='PNG')
            b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            return render_template('result.html',
                                   structured=False, qr=b64, color=color, version=version)
        else:
            # Now generate a QR using either 'payload' (HTML‐wrapped) or 'raw_text' (plain)
            qr_img = generate_qr_img(payload, version, ecc, color, logo_file)
            buf = io.BytesIO()
            qr_img.save(buf, format='PNG')
            b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
            return render_template('result.html',
                                   structured=False, qr=b64, color=color, version=version)


@app.route('/template')
def template():
    # ?color=white or ?color=black
    color = request.args.get('color', 'white').lower()
    if color not in ['white', 'black']:
        color = 'white'
    bg_color = (255, 255, 255) if color == 'white' else (0, 0, 0)

    width_px  = int(round(86  / 25.4 * 300))  # ≈ 1015 px
    height_px = int(round(54  / 25.4 * 300))  # ≈ 638 px

    img = Image.new('RGB', (width_px, height_px), color=bg_color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    response = make_response(buf.read())
    response.headers.set('Content-Type', 'image/png')
    filename = f'card_{color}_{width_px}x{height_px}.png'
    response.headers.set('Content-Disposition', 'attachment', filename=filename)
    return response


if __name__ == '__main__':
    app.run(debug=True)
