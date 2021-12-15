FROM ruby:3.0

WORKDIR /usr/src/app
COPY ./log4j.rb .
COPY Gemfile .
COPY ./docker-entrypoint.sh .
RUN apt-get update && apt-get install netcat -y
RUN bundle install
CMD ["/bin/bash", "./docker-entrypoint.sh"]
