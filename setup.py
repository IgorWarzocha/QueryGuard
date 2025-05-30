# setup.py
from setuptools import setup, find_packages
import pathlib # More modern way to handle paths

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README_TEXT = (HERE / "README.md").read_text(encoding='utf-8')

# Read the contents of your requirements file
with open(HERE / 'requirements.txt', encoding='utf-8') as f:
    required_dependencies = f.read().splitlines()

# Automatically extract version from queryguard/__init__.py
def get_version():
    version_file = HERE / 'queryguard' / '__init__.py'
    with open(version_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('__version__'):
                # Crude parser: __version__ = "0.1.0"
                delim = '"' if '"' in line else "'"
                return line.split(delim)[1]
    raise RuntimeError("Unable to find version string.")

VERSION = get_version()

setup(
    name='queryguard',
    version=VERSION,
    author='Igor Warzocha',
    author_email='igorwarzocha@gmail.com',
    description='A pre-LLM input filtering and validation library to mitigate abuse and enhance security.',
    long_description=README_TEXT,
    long_description_content_type='text/markdown',
    url='https://github.com/igorwarzocha/queryguard-library', # Example GitHub URL
    # find_packages() will find the 'queryguard' package in the 'queryguard' directory
    packages=find_packages(exclude=['tests*', 'examples*', 'docs*']),
    install_requires=required_dependencies,
    license='MIT', # Should match the LICENSE file
    classifiers=[
        'Development Status :: 2 - Pre-Alpha', # Indicates early development stage
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
        'Topic :: Text Processing :: Filters',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
    keywords='llm, ai, security, guardrails, prompt injection, input validation, queryguard, llm-security, pre-llm-filter',
    project_urls={ # Optional, but good for users
        'Bug Reports': 'https://github.com/igorwarzocha/queryguard-library/issues',
        'Source Code': 'https://github.com/igorwarzocha/queryguard-library/',
        # 'Documentation': 'https://queryguard.readthedocs.io/', # Example if you host docs
    },
    # If your package has entry points (e.g., command-line scripts), define them here:
    # entry_points={
    #     'console_scripts': [
    #         'queryguard-cli=queryguard.cli:main', # Example
    #     ],
    # },
)
