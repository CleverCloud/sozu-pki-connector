# Sōzu pki connector

> This application retrieves pki (public key infrastructure) in a directory and loads them into Sōzu

## Status

The connector is under development, it is not yet ready for production.

## Configuration

We suggest you rename [`example.config.toml`](./example.config.toml)
to `pki.toml` and put it in `/etc/sozu/connector/`:

```
mkdir /etc/sozu
mkdir /etc/sozu/connector/
cp example.config.toml /etc/sozu/connector/pki.toml
```

Set the values. You can set these things:

- watching the pki directory:
    - its path
    - the check intervals
- the metrics server's address
- the path to Sōzu's configuration
- the address of the HTTPS listener where Sōzu will load it's certificates

## Usage

Once you have installed the `sozu-pki-connector` and followed the configuration indication,
you can start it with the following command.

```
sozu-pki-connector -vvv -c /etc/sozu/connector/pki.toml
```

## License

See the [`LICENSE`](./LICENSE) file

## Getting in touch

- Twitter: [`@FlorentinDUBOIS`](https://twitter.com/FlorentinDUBOIS)
