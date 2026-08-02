from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='engin33r',
    version='0.1.0',
    description='Complete framework for bug vulnerability identification, analysis, and management',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='atryxdean',
    url='https://github.com/atryxdean/engin33r',
    packages=find_packages(),
    python_requires='>=3.8',
    install_requires=[
        'pydantic>=1.10.0',
        'requests>=2.28.0',
        'pyyaml>=6.0',
        'colorama>=0.4.6',
        'tabulate>=0.9.0',
    ],
    extras_require={
        'dev': [
            'pytest>=7.0',
            'pytest-cov>=4.0',
            'black>=22.0',
            'flake8>=5.0',
            'mypy>=0.990',
        ],
        'ml': [
            'scikit-learn>=0.24',
            'numpy>=1.19',
            'joblib>=1.0',
            'pandas>=1.1',
        ],
    },
    entry_points={
        'console_scripts': [
            'engin33r=engin33r.cli:main',
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Monitoring',
    ],
)
