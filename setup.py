from setuptools import setup, find_packages

setup(
    name="ai-tracer",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "web3>=5.29.0",
        "ipfshttpclient>=0.8.0a2",
        "py-solc-x>=1.1.1",
    ],
    author="Your Name",
    author_email="your.email@example.com",
    description="AI-Tracer: 基于区块链的AI行为可信追踪框架",
    keywords="blockchain, AI, tracking, proxy re-encryption, Schnorr",
    python_requires=">=3.7",
)