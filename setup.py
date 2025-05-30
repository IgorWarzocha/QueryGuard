# setup.py
from setuptools import setup, find_packages

# Read the contents of your README file
from pathlib import Path
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read the contents of your requirements file
with open('requirements.txt', encoding='utf-8') as f:
    required = f.read().splitlines()

setup(
    name='queryguard',
    version='0.0.1-alpha', # Should match queryguard/__init__.py
    author='[Igor Warzocha]', # Replace
    author_email='[igorwarzocha@gmail.com]',   # Replace
    description='A pre-LLM input filtering and validation library to mitigate abuse.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/yourusername/queryguard-library', # Replace with your repo URL
    packages=find_packages(exclude=['tests*', 'examples*']), # Finds the 'queryguard' package
    install_requires=required,
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Security',
        'Topic :: Scientific/Engineering :: Artificial Intelligence',
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
    keywords='llm, ai, security, guardrails, prompt injection, input validation, queryguard',
    project_urls={ # Optional
        'Bug Reports': 'https://github.com/yourusername/queryguard-library/issues',
        'Source': 'https://github.com/yourusername/queryguard-library/',
    },
)