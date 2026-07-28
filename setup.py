from setuptools import setup

setup(
    name='certbot-dns-opteamax',
    version = '2.0.2',
    author='Peter Lieven',
    author_email='pl@opteamax.de',
    py_modules=['certbot_dns_opteamax'],
    url     = 'https://github.com/plieven/certbot-dns-opteamax',
    install_requires=[
        'certbot',
    ],
    entry_points={
        'certbot.plugins': [
            'dns-opteamax = certbot_dns_opteamax:Authenticator',
        ],
    },
)
