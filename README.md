# PROJETO INTEGRADOR | SEGURANÇA APLICADA AO DESENVOLVIMENTO
## Entrega 1: Criptografia assimétrica e confiança

O código fica em [entrega-1](entrega-1/), e as evidências de execução em [entrega-1/evidencias](entrega-1/evidencias/).

### Problema e requisitos

Situação-problema: Uma aplicação precisa proteger uma mensagem enviada a outro serviço e verificar sua autenticidade.

Requisitos mínimos: Gerar par de chaves; implementar cifragem híbrida (por exemplo, AES-GCM para o conteúdo e RSA-OAEP para encapsular a chave) OU
assinatura digital com Ed25519/RSA-PSS; demonstrar sucesso e falha após adulteração; explicar diferença entre sigilo e autenticidade; descrever a função de
certificados digitais e PKI. 

Produto: Código funcional, demonstração, README com algoritmos, parâmetros,
gestão de chaves e limites da solução. 

### Ambiente e tecnologias

| Item | Versão ou uso |
| --- | --- |
| Sistema usado nos testes | Windows 11 |
| Python | 3.13.18 |
| [cryptography](https://cryptography.io/) | 50.0.2, todas as operações criptográficas |
| pytest | 9.2.0, testes automatizados |
| [uv](https://docs.astral.sh/uv/) | Instalação do Python e das dependências, com versões fixadas em `uv.lock` |

### Algoritmos, parâmetros e justificativa

| Finalidade | Algoritmo | Parâmetros | Justificativa |
| --- | --- | --- | --- |
| Cifrar o conteúdo | AES-GCM | Chave de 256 bits e nonce de 96 bits, ambos novos a cada mensagem | Cifra com autenticação: detecta alterações e é rápida para mensagens de qualquer tamanho |
| Proteger a chave AES | RSA-OAEP | Chave de 3072 bits, expoente 65537, SHA-256 e MGF1 com SHA-256 | Permite enviar a chave AES a quem tem a chave privada. O OAEP é o preenchimento recomendado para cifragem com RSA |
| Assinar | Ed25519 | Parâmetros fixos do algoritmo | Assinaturas curtas e rápidas, sem parâmetros que possam ser mal configurados |
| Proteger as chaves privadas | PKCS#8 cifrado com `BestAvailableEncryption` | Na versão usada: PBES2, PBKDF2 com HMAC-SHA256 e AES-256-CBC | Um arquivo de chave vazado não pode ser usado sem a senha |

O RSA não é adequado para cifrar mensagens longas diretamente. Por isso, a cifragem é híbrida: o AES cifra o conteúdo, e o RSA protege apenas a chave AES.

Cada par de chaves tem uma única finalidade: o RSA é usado na cifragem, e o Ed25519, na assinatura.

#### Sigilo e autenticidade

- **Sigilo** garante que apenas quem tem a chave certa consiga ler o conteúdo. Neste projeto, ele vem da cifragem híbrida.
- **Autenticidade** garante quem produziu a mensagem e que ela não foi alterada. Neste projeto, ela vem da assinatura Ed25519, verificada com a chave pública do remetente.

Um mecanismo não substitui o outro:

- A cifragem híbrida sozinha não prova o remetente. A chave pública é pública, então qualquer pessoa pode cifrar uma mensagem válida. O AES-GCM detecta alterações no conteúdo cifrado, mas não identifica quem o criou.
- A assinatura sozinha não oferece sigilo, porque a mensagem continua legível.

Para obter os dois, é preciso combinar os mecanismos. Com a opção `--sign`, este projeto primeiro cifra a mensagem e depois assina o pacote cifrado. O destinatário verifica a assinatura antes de decifrar.

#### Certificados digitais e PKI

A criptografia assimétrica depende de saber a quem pertence uma chave pública. Se um atacante substituir a chave pública do destinatário pela dele, poderá ler as mensagens cifradas. Se substituir a do remetente, poderá assinar em seu nome.

- **Certificado digital:** documento, normalmente no padrão X.509, que liga uma chave pública a uma identidade, com prazo de validade e a assinatura de quem o emitiu.
- **PKI (infraestrutura de chaves públicas):** conjunto de autoridades certificadoras, políticas e processos que emite, valida e revoga certificados.
- **Cadeia de confiança:** quem verifica o certificado confere as assinaturas até chegar a uma autoridade raiz em que já confia, além da validade e da revogação.

Este projeto não usa certificados nem PKI. As chaves públicas são lidas de arquivos locais e consideradas confiáveis.

### Implementação e execução

| Arquivo | Função |
| --- | --- |
| [key_gen.py](entrega-1/key_gen.py) | Gera, salva e carrega as chaves |
| [encrypt.py](entrega-1/encrypt.py) | Funções `cypher` e `decypher` |
| [signature.py](entrega-1/signature.py) | Funções `sign` e `verify` |
| [package_file.py](entrega-1/package_file.py) | Salva, lê e adultera o pacote cifrado em arquivo |
| [exec_cypher.py](entrega-1/exec_cypher.py) | Cifra e assina a mensagem, ou adultera um pacote já cifrado |
| [exec_decypher.py](entrega-1/exec_decypher.py) | Verifica a assinatura e restaura a mensagem |
| [test_entrega1.py](entrega-1/test_entrega1.py) e [test_exec.py](entrega-1/test_exec.py) | Testes automatizados |

#### Preparação

Instale as dependências:

```bash
uv sync
```

Defina a senha das chaves privadas, com no mínimo 8 caracteres, a cada novo terminal. A opção `-MaskInput` requer o PowerShell 7:

```powershell
$env:KEY_PASSWORD = Read-Host "Senha das chaves" -MaskInput
```

### Execução

| Script | Parâmetro | Função |
| --- | --- | --- |
| `exec_cypher.py` | `"mensagem"` | Cifra a mensagem e salva o pacote em `entrega-1/data/mensagem.json`, substituindo o anterior |
| `exec_cypher.py` | `--sign` | Assina o pacote cifrado; exige uma mensagem |
| `exec_cypher.py` | `--tamper` | Altera um bit do conteúdo cifrado. Sem mensagem, age sobre o pacote já salvo |
| `exec_decypher.py` | `--require-signature` | Rejeita mensagens sem assinatura |
| Ambos | `--file caminho` | Usa outro arquivo de pacote |

O `exec_cypher.py` gera as chaves em `entrega-1/keys/` se não houver nenhuma. O `exec_decypher.py` nunca gera chaves, porque chaves novas não decifrariam uma mensagem antiga.

Cifrar e assinar uma mensagem:

```bash
uv run python entrega-1/exec_cypher.py "mensagem de teste" --sign
```

Restaurar a mensagem:

```bash
uv run python entrega-1/exec_decypher.py
```

```text
Assinatura válida
Mensagem decifrada: mensagem de teste
```

Adulterar a mensagem já cifrada:

```bash
uv run python entrega-1/exec_cypher.py --tamper
```

Tentar restaurar de novo:

```bash
uv run python entrega-1/exec_decypher.py
```

```text
Falha: assinatura inválida; o pacote foi alterado ou não veio deste remetente.
```

Sem `--sign`, a adulteração é detectada pelo AES-GCM, com a mensagem `Falha: adulteração detectada no conteúdo cifrado.` Nesse caso, uma mensagem íntegra é restaurada com um aviso de que a origem não foi verificada. As falhas terminam o script com código de saída 1.

(Opcional) Gere as chaves separadamente. O comando falha se alguma chave já existir:

```bash
uv run python entrega-1/key_gen.py
```

#### Gestão de chaves

- **Geração:** feita localmente pela biblioteca `cryptography`.
- **Armazenamento:** arquivos PEM em `entrega-1/keys/`, fora do versionamento pela regra `*.pem` do `.gitignore`. As chaves privadas ficam cifradas com a senha.
- **Senha:** fornecida na execução pela variável `KEY_PASSWORD`, sem ser gravada em arquivo. O ideal é guardá-la em um gerenciador de senhas.
- **Proteção contra perda:** o script não sobrescreve chaves existentes e para com erro se o conjunto estiver incompleto.
- **Perda da senha:** as chaves privadas não podem ser recuperadas, nem o que foi cifrado com elas.

### Testes e evidências

Execute os testes automatizados, que usam chaves temporárias e não precisam da senha:

```bash
uv run pytest
```

Os testes cobrem:

- cifragem e decifragem, com chave e nonce novos a cada mensagem;
- adulteração do conteúdo, do nonce e da chave AES cifrada, além do uso da chave privada errada;
- assinatura válida, mensagem alterada, assinatura alterada e chave pública errada;
- geração e reutilização de chaves, proteção por senha, não sobrescrita, conjunto incompleto e senha ausente ou curta;
- os scripts de execução: restauração de mensagens, adulteração de um pacote já salvo, assinatura removida, arquivo inválido e parâmetros incorretos.

| Evidência | O que comprova |
| --- | --- |
| [testes.txt](entrega-1/evidencias/testes.txt) | Resultado dos testes automatizados |
| [chave_cifrada.txt](entrega-1/evidencias/chave_cifrada.txt) | A chave privada está cifrada no disco (somente a primeira linha do arquivo) |
| [chaves_ignoradas.txt](entrega-1/evidencias/chaves_ignoradas.txt) | As chaves ficam fora do versionamento |
| `demonstracao.txt` | Saída do fluxo de cifrar, restaurar, adulterar e rejeitar |

### Riscos, limitações e melhorias

| Limitação | Risco | Melhoria |
| --- | --- | --- |
| Sem certificados nem PKI | Uma chave pública substituída seria aceita | Distribuir as chaves em certificados X.509 validados |
| Demonstração em uma única máquina, com o arquivo no lugar do envio entre serviços e todas as chaves na mesma pasta | O envio real e seus riscos não foram testados | Transmitir o pacote por TLS e deixar em cada serviço apenas as próprias chaves privadas |
| A assinatura é opcional, salvo com `--require-signature` | Quem remove a assinatura transforma o pacote em uma mensagem sem origem verificada | Exigir a assinatura em todo recebimento |
| A assinatura cobre o pacote cifrado, não a mensagem original | Ela comprova quem produziu o pacote, mas não prova, para terceiros, o que estava escrito nele | Usar um protocolo pronto, como mTLS ou JWE com JWS |
| Sem proteção contra repetição | Uma mensagem válida capturada pode ser reenviada | Incluir identificador único, data e hora, e rejeitar repetições |
| Senha única em variável de ambiente, com mínimo de 8 caracteres | Senha fraca facilita ataques offline a um arquivo vazado, e outros processos do mesmo usuário podem ler a variável | Exigir senhas mais longas e usar um cofre de segredos ou KMS |
| Permissões dos arquivos não são restringidas pelo script | Outros usuários podem conseguir copiar as chaves cifradas | Restringir o acesso à pasta ou usar um HSM ou KMS |
| Sem rotação nem revogação de chaves | Uma chave comprometida continuaria válida | Definir validade, rotação e revogação |
| RSA e Ed25519 não são resistentes a computadores quânticos | Dados guardados hoje podem ser expostos no futuro | Planejar a migração para algoritmos pós-quânticos |
