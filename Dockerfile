FROM amazonlinux:2
WORKDIR /App

RUN yum update -y

RUN yum groupinstall "Development Tools" -y
RUN yum erase openssl-devel -y
RUN yum install openssl11 openssl11-devel  libffi-devel bzip2-devel wget -y

RUN yum install wget -y
RUN yum install zip -y

RUN wget https://www.python.org/ftp/python/3.10.4/Python-3.10.4.tgz
RUN tar -xf Python-3.10.4.tgz
RUN cd Python-3.10.4 && \
    bash ./configure --enable-optimizations && \
    make -j $(nproc) && \
    make altinstall 

RUN python3.10 --version

RUN yum install python3-pip -y

RUN cd / && \
    mkdir layer && \
    cd layer && \
    mkdir python

# Install python packages below
RUN cd /layer/python/ && \
pip3.10 install python-multipart -t .  && \
pip3.10 install PyJWT -t . && \
pip3.10 install cffi -t . && \
pip3.10 install dynamodb_json -t . &&\
pip3.10 install cryptography -t . && \ 
pip3.10 install elasticsearch -t .

# End installing python packages below

RUN cd /layer/ && \
    zip -r layer.zip .

RUN cd /