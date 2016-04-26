from __future__ import unicode_literals
from distutils.core import setup

__version__ = '0.2.0'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''


setup(
    name='pywinrm',
    version=__version__,
    description='Python library for Windows Remote Management',
    long_description=long_description,
    keywords='winrm ws-man devops ws-management'.split(' '),
    author='Alexey Diyan',
    author_email='alexey.diyan@gmail.com',
    url='http://github.com/diyan/pywinrm/',
    license='MIT license',
    packages=('winrm', 'tests'),
    package_data={'tests': ['*.ps1']},
    install_requires=['xmltodict', 'requests'],
    extras_require = dict(
        ntlm=['requests_ntlm>0.2.0'],
        kerberos=['requests_kerberos>0.8.0'],
    ),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Clustering',
        'Topic :: System :: Distributed Computing',
        'Topic :: System :: Systems Administration'
    ],
)
