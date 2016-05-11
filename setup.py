"""

"""

from setuptools import setup, find_packages

with open('README.rst') as f:
    readme = f.read()


setup(
    name='vinli_tornado_auth',
    version='0.1.0',
    description='Tornado web authentication for the Vinli Platform.',
    long_description=readme,
    author='Greg Aker',
    author_email='greg@gregaker.net',
    url='https://github.com/gaker/vinli-tornado-auth',
    download_url='https://github.com/gaker/vinli-tornado-auth/archive/0.1.0.tar.gz',
    packages=find_packages(),
    classifiers=[
        'License :: OSI Approved :: MIT License',
        'Environment :: Web Environment',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
    ]
)
