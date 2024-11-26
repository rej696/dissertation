FROM aflplusplus/aflplusplus:latest

RUN wget --output-document /opt/arm-none-eabi.tar.xz "https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi.tar.xz"
RUN cd /opt && tar xvf arm-none-eabi.tar.xz

ADD requirements.txt /etc/requirements.txt
RUN pip install -r /etc/requirements.txt

RUN find /opt/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi/bin/ -name "*" -exec ln -vs {} /usr/local/bin/ ';'

WORKDIR /src
