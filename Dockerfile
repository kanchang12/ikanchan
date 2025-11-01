FROM kalilinux/kali-rolling

# Install Python
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nikto \
    nmap \
    sqlmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Wapiti
RUN pip3 install wapiti3

# Install testssl.sh
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip && \
    unzip nuclei_3.1.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.1.0_linux_amd64.zip

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY . .

ENV PORT=8080
ENV PYTHONUNBUFFERED=1

CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 600 app:app
