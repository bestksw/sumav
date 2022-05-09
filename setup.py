from setuptools import setup, find_packages
from pathlib import Path

version = {}
with open('sumav/version.py') as f:
    exec(f.read(), version)
    VERSION = version['__version__']

with open('README.md') as f:
    README = f.read()

setup(
    name='sumav',
    version=VERSION,
    description=('Sumav is a fully automated labeling tool that assigns each '
                 'file a family name based on AV labels.'),
    long_description_content_type='text/markdown',
    long_description = README,
    url='https://github.com/bestksw/sumav',
    author='Sangwon Kim',
    author_email='bestksw@gmail.com',
    license='Apache 2.0',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
    ],
    keywords='summerize detecion anti-virus software virustotal labeling',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    include_package_data=True,
    install_requires=['psycopg2-binary', 'requests'],
    python_requires='>=3.4',
    entry_points={
        'console_scripts': [
            'sumav=sumav.console:console_main'
        ],
    },
)
