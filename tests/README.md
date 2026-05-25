# Tests

## Struktur

```
tests/
  test_pubkey_auth.py          Unit-Tests: publickey-Authentifizierung
  test_exec_handler_registry.py  Unit-Tests: Exec-Handler-Registry
  test_exec_handler_filter.py    Unit-Tests: Exec-Handler-Filter
  integration/
    conftest.py                Fixtures für Integrationstests
    test_trivial_auth.py       Integrationstest: Trivial-Auth End-to-End
```

## Unit-Tests ausführen

```bash
pytest
```

Die Unit-Tests haben keine externen Abhängigkeiten. Ein laufender SSH-Server oder
eine Netzwerkverbindung ist nicht erforderlich.

## Integrationstests ausführen

```bash
pytest tests/integration/
```

Die Integrationstests sind im Standard-Run über `addopts = "--ignore=tests/integration"`
in `pyproject.toml` ausgeschlossen.

### Voraussetzungen

- `ssh-mitm` muss im aktiven Python-Environment installiert sein (`pip install .`)
- OpenSSH-Client (`ssh`) muss verfügbar sein
- Ein SSH-Agent muss laufen und einen gültigen Key geladen haben

Der OpenSSH-Client ist der einzige externe Prozess. Alles andere
(SSH-Zielserver, SSH-Agent) wird vom Test selbst gestartet.

## Testarchitektur

### Unit-Tests (`test_pubkey_auth.py`)

Die Unit-Tests instanziieren `ServerInterface` direkt mit gemockten Sessions und
rufen Methoden ohne Netzwerk-Stack auf.

Klassen:

| Klasse | Was wird getestet |
|---|---|
| `TestDispatcher` | Routing über `sig_attached` (pk_lookup vs. authenticate) |
| `TestPkLookup` | `check_auth_publickey_pk_lookup`: alle Gate-Checks, Key-Logging, Remote-Probe |
| `TestAuthenticate` | `check_auth_publickey_authenticate`: Cache-Hit, accept_first, disallow |
| `TestRfc4252DirectSignature` | Client überspringt pk_lookup und sendet Signatur direkt |
| `TestEndToEnd` | Echter paramiko-Transport gegen In-Process-Mock-Server |
| `TestTrivialAuth` | `check_auth_interactive` / `check_auth_interactive_response` im Trivial-Auth-Flow |

### Integrationstests (`integration/`)

Der vollständige Stack ohne externes OpenSSH:

```
ssh (OpenSSH subprocess, -A)
       ↓  trivial auth: probe → AUTH_FAILED → kbd-interactive (leer) → SUCCESS
   ssh-mitm (subprocess)
       ↓  agent forwarding über Unix-Socket → FakeAgent → paramiko-Signierung
   Mock-SSH-Server (paramiko, im Test-Prozess)
```

**Schlüsselmanagement** — alles wird vom Test selbst erzeugt, nichts liegt
vorkonfiguriert auf dem Dateisystem:

| Was | Wie |
|---|---|
| Mock-Target Host-Key | `paramiko.RSAKey.generate()` im Session-Fixture |
| Client-Key | `paramiko.RSAKey.generate()` im Session-Fixture |
| SSH-Agent | `FakeAgent`: Unix-Socket-Server, signiert mit `paramiko.PKey.sign_ssh_data()` |
| `SSH_AUTH_SOCK` | wird im `fake_agent`-Fixture gesetzt und danach wiederhergestellt |
| ssh-mitm Host-Key | wird von ssh-mitm selbst temporär generiert |

#### Trivial-Auth-Flow

Trivial Auth ist ein Phishing-Angriff:

1. **pk_lookup**: MITM prüft den Key beim Zielserver → gültig → `accepted_key` gesetzt →
   gibt dennoch `AUTH_FAILED` zurück, damit der Client auf kbd-interactive fällt
2. **keyboard-interactive**: MITM sendet leere Challenge (0 Prompts)
3. **Response**: Client antwortet leer → MITM ruft `authenticate(key=None)` → `AUTH_SUCCESSFUL`
4. **Agent-Forwarding**: Client leitet Agent weiter → MITM nutzt ihn zur Authentifizierung
   am echten Zielserver

Ohne Agent-Forwarding kann sich der MITM nicht beim Zielserver authentifizieren,
da er nie im Besitz des privaten Schlüssels war.

#### Hinweis zu `saved-from-auth-signature`

OpenSSH kann nach einem fehlgeschlagenen Probe gemäß RFC 4252 einen erneuten
Versuch mit `sig_attached=True` senden. Der MITM lehnt ihn korrekt ab
(`check_auth_publickey_authenticate` gibt `AUTH_FAILED` zurück, weil Trivial-Auth
aktiv ist). Die Session wird trotzdem über kbd-interactive aufgebaut.
Das Vorhandensein eines `saved-from-auth-signature`-Eintrags im Key-Log ist daher
kein Fehler.
