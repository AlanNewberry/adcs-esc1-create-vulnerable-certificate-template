# AD CS ESC1 - Crear Template de Certificado Vulnerable desde Cero

## Descripcion

Escribi este script como alternativa al clonado de templates. En vez de clonar uno existente, crea un template de certificado completamente nuevo con todos los atributos necesarios para explotar ESC1, incluyendo la configuracion de security descriptor, EKU, y flags. Es util cuando no tenes permisos para leer templates existentes pero si para crear nuevos.

## Como funciona

1. **Construccion del Security Descriptor**: Arma un SD binario con ACLs que permiten enrollment a Authenticated Users
2. **Conexion LDAPS**: Se conecta al DC con NTLM
3. **Creacion del template**: Agrega el objeto al contenedor de Certificate Templates con todos los atributos PKI configurados para ESC1:
   - `msPKI-Certificate-Name-Flag = 1` → enrollee supplies subject
   - `msPKI-Enrollment-Flag = 0` → sin aprobacion
   - `pKIExtendedKeyUsage = 1.3.6.1.5.5.7.3.2` → Client Authentication
   - Schema Version 1 (sin firma de RA requerida)

## Requisitos

```bash
pip install ldap3 impacket
```

## Uso

Configura `TEMPLATE_NAME` y `OWNER_SID` en el script, luego:

```bash
python3 adcs-esc1-create-vulnerable-certificate-template.py <DC_IP> <dominio> <usuario> <password>
```

## Ejemplo de salida

```
[i] SD bytes: 112
[+] bound
[+] CREATED (ESC1): CN=CustomTemplate,CN=Certificate Templates,...
```

## Diferencia con el script de clonado

| Caracteristica | Clonar template | Crear desde cero |
|---|---|---|
| Requiere leer templates existentes | Si | No |
| Complejidad | Menor | Mayor |
| Control sobre atributos | Parcial (hereda del original) | Total |
| Deteccion | Mas dificil | Mas facil (template sin historial) |

## Nota importante

Despues de crear el template, necesitas vincularle un OID. Usa el script `adcs-oid-certificate-template-linking` para completar la configuracion.

## Aviso legal

Este script es unicamente para pruebas de seguridad autorizadas y fines educativos. Siempre obtene la autorizacion correspondiente antes de testear contra cualquier sistema.

## Autor

**Alan Newberry**
