from setuptools import setup


setup(
    name="crlite-status",
    version="0.0.2",
    description="Query CRLite status",
    long_description="Use this tool get information about recent CRLite runs",
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Programming Language :: Python :: 3",
    ],
    keywords="bloom filter cascade multi level mlbf crlite",
    url="http://github.com/jcjones/crlite-status",
    author="J.C. Jones",
    author_email="jc@insufficient.coffee",
    license="Mozilla Public License 2.0 (MPL 2.0)",
    zip_safe=False,
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=["requests>=2.10", "rich>=3.0"],
    packages=["crlite_status"],
    entry_points={"console_scripts": ["crlite_status=crlite_status.status:main"]},
)
