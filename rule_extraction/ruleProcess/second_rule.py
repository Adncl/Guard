import argparse
import pandas as pd
from openai import OpenAI
from tqdm import tqdm

def run_second_rule(api_key, protocol, version):
    # Read Excel file
    df = pd.read_excel("directoryStore/filtered_sentences.xlsx", engine='openpyxl')

    matched_sentences = df[df["Is_Matched"] == True]["Sentence"].tolist()

    print(f"Total matched sentences to process: {len(matched_sentences)}")

    # Initialize OpenAI client
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com/v1")

    def analyze_sentence(sentence):
        prompt = f"""
        You are provided with a set of descriptions extracted from the {protocol} {version} protocol specification:
        {sentence}

        Your task is to analyze the meaning of each rule in these descriptions and determine whether it falls within our scope of interest. 
        You must follow this analysis process step-by-step for each rule:
        1. The rule describes a specific {protocol} protocol message type or its internal fields, and this message type can be received by an {protocol} protocol server implementation.
        2. The rule explicitly describes or implies, through field value ranges or format definitions, the processing logic that the protocol program should apply after receiving the input message. This logic must be detailed enough to directly guide a developer's implementation.
        3. The described message processing logic pertains to a single message handling flow, without involving concurrency, subsequent input message types, or historical state dependencies.

        For each rule:
        - If all three criteria (1, 2, and 3) are satisfied, respond with "Conforms."
        - If any criterion is not met, respond with "Does not conform."

        Please omit all explanatory content.
        """

        # print(prompt)  # Debug: print the prompt being sent

        try:
            response = client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {"role": "user", "content": prompt}
                ],
                stream=False
            )

            model_output = response.choices[0].message.content.strip()
            conforms = "Conforms" in model_output
            
            # print("conforms:", conforms, "model_output:", model_output)

            return conforms, model_output

        except Exception as e:
            print(f"Error processing sentence: {sentence}\nException: {e}")
            return False, f"Error: {str(e)}"

    # Initialize new column
    df["Second_Filter_Result"] = "Pending"
    df.to_excel("directoryStore/filtered_sentences.xlsx", index=False, engine='openpyxl')

    # Process matched sentences
    for sentence in tqdm(matched_sentences, desc="Processing Sentences"):
        conforms, output = analyze_sentence(sentence)
        result_text = "Conforms" if conforms else "Does not conform"
        df.loc[df["Sentence"] == sentence, "Second_Filter_Result"] = result_text
        df.to_excel("directoryStore/filtered_sentences.xlsx", index=False, engine='openpyxl')
        print(f"Processed: {sentence} -> {result_text}")

    print("Filtering completed, results saved.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Protocol Rule Validation")
    parser.add_argument("--apikey", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    run_second_rule(args.apikey, args.protocol, args.version)