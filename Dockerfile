FROM python:3.6.3

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY requirements*.txt /usr/src/app/
RUN pip install -i https://pypi.dm.gg/dm/prod --no-cache-dir -r requirements-dev.txt -r requirements.txt

COPY . /usr/src/app

EXPOSE "80"
CMD [ "python", "-m", "service" ]
