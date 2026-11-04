# Projeto Integrador: Segurança Aplicada ao Desenvolvimento

## Entrega 1: Criptografia assimétrica e confiança

O código fica em [entrega-1](entrega-1/), e as evidências de execução em `entrega-1/evidencias/`.

## Pré-requisitos

- [uv](https://docs.astral.sh/uv/) (instala o Python 3.13 e as dependências)

## Preparação

```bash
uv sync
```

## Execução

```bash
uv run python entrega-1/exec_encrypt.py
```

## Geração de chaves

Defina a senha das chaves privadas (mínimo de 8 caracteres) na variável `KEY_PASSWORD` e execute o script. As chaves são salvas em `entrega-1/keys/`, fora do versionamento. O script não sobrescreve chaves existentes.

```powershell
$env:KEY_PASSWORD = Read-Host "Senha das chaves"
```

```bash
uv run python entrega-1/key_gen.py
```

## Regras do projeto

- Não usar dados reais nem credenciais de terceiros.
- Usar bibliotecas criptográficas consolidadas; não implementar algoritmos próprios.
