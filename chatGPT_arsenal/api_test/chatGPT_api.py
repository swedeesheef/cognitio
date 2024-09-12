import openai
import json
import os

# Set up your OpenAI API key
openai.api_key = os.getenv("OPENAI_API_KEY")  # Make sure to set your API key as an environment variable for security

# Function to generate ideas using the OpenAI API
def generate_cybersec_ideas():
    try:
        # Define the prompt for offensive cybersecurity tool ideas
        prompt = (
            "Generate several creative ideas for offensive cybersecurity tools that could be written in Python. "
            "For each tool, provide a name, a brief description, potential use cases, and relevant Python libraries or modules."
        )

        # Send the request to OpenAI API using gpt-3.5-turbo model
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=500,
            n=1,
            stop=None,
            temperature=0.7
        )

        # Extract the generated text from the response
        generated_text = response['choices'][0]['message']['content'].strip()

        # Split and format the ideas into a structured JSON object
        ideas = []
        for idea in generated_text.split('\n\n'):
            if idea.strip():
                lines = idea.split('\n')
                tool_name = lines[0].strip(":-")
                description = lines[1].strip() if len(lines) > 1 else "No description available"
                use_cases = lines[2].strip() if len(lines) > 2 else "No use cases available"
                libraries = lines[3].strip() if len(lines) > 3 else "No libraries mentioned"
                
                # Append the structured idea
                ideas.append({
                    "tool_name": tool_name,
                    "description": description,
                    "use_cases": use_cases,
                    "libraries": libraries
                })

        # Return the structured ideas
        return ideas

    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# Function to save the generated ideas as a JSON file
def save_to_json(data, filename="cybersec_tool_ideas.json"):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"Data saved to {filename}")
    except Exception as e:
        print(f"An error occurred while saving the file: {e}")

if __name__ == "__main__":
    # Generate the cybersecurity tool ideas
    ideas = generate_cybersec_ideas()

    if ideas:
        # Save the ideas to a JSON file
        save_to_json(ideas)
    else:
        print("No ideas were generated.")

