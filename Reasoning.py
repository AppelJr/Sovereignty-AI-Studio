from openai import OpenAI

client = OpenAI(api_key="YOUR_API_KEY_HERE")

chat = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
    store=True,
)
print(chat.choices[0].message.content)
