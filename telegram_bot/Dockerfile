FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10002 ratscan-bot

WORKDIR /app
COPY telegram_bot/requirements.txt ./telegram_bot/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore -r telegram_bot/requirements.txt

COPY telegram_bot ./telegram_bot
RUN chown -R ratscan-bot:ratscan-bot /app

USER ratscan-bot

CMD ["python", "-m", "telegram_bot.bot"]
