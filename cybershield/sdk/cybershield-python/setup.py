from setuptools import setup

setup(
    name="cybershield-python",
    version="2.0.0",
    description="CyberShield Universal — Python SDK (Flask, Django, FastAPI, WSGI)",
    long_description=open("README.md").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="CyberShield",
    py_modules=["cybershield_python"],
    python_requires=">=3.8",
    install_requires=[],   # stdlib only — no extra deps
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Framework :: Flask",
        "Framework :: Django",
    ],
)
