# prmove

GitHub Pull Request Mover, specifically for the Ansible repo consolidation

## Configuration

```
GITHUB_CLIENT_ID = '1ecad3b34f7b437db6d0'
GITHUB_CLIENT_SECRET = '6689ba85bb024d1b97370c45f1316a16d08bba20'
SECRET_KEY = '\\{\x86m\x01\xc7\xe6\xa1\x19\x93\xe3F\xf5\x192)\x87k0\xdd\xcb\x1d\x10%'
```

### GitHub credentials

You will need to [register an application](https://github.com/settings/applications/new)
to provide API access.  The Client ID and Secret will need to be populated as
shown in the above example.

#### Development

When registering for local development you can use the following values:

- Hompage URL: `http://127.0.0.1:5000/`
- Authorization callback URL: `http://127.0.0.1:5000/login/authorized`

### Secret Key

This is just some secret key to use as a salt for encryption, use something like `os.urandom(32)`.

If you run this on multiple servers, make sure this value matches across all servers.

## Installation/Running

1. `virtualenv prmove --python /path/to/python3`
1. `. prmove/bin/activate`
1. `pip install -r requirements.txt`

### CLI

`cli.py` still requires all of the above requirements, including flask, but won't actually use them. I'm lazy what can I say?

### Development

Running via flask for development:

1. `PRMOVE_CONFIG=/path/to/config.conf python3 prmove.py`


### Production

Running via a wsgi server such as gunicorn is recommended, and potentially behind a proxy such as nginx.

1. `pip install gunicorn gevent`
1. `gunicorn -k gevent -e 'PRMOVE_CONFIG=/path/to/config.py' prmove:app`

#### nginx

```
upstream prmove {
    least_conn;
    server 1.2.3.4:8000;
    server 5.6.7.8:8000;
}

server {
    listen 80;
    listen 443 ssl;
    server_name prmove.example.org;

    if ( $scheme != "https" ) {
        rewrite /(.*) https://$host/$1 permanent;
    }

    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $http_host;
    proxy_redirect off;

    location / {
        try_files $uri $uri/ @pass_to_prmove;
    }

    location @pass_to_prmove {
        proxy_pass http://prmove;
        proxy_read_timeout 300s;
        client_max_body_size 1m;
    }
}
```

### Local Dev Mode

1. `PRMOVE_CONFIG=/path/to/config.py python3 prmove.py`
