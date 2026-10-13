import json
import re
import pandas as pd

count = 0
cnt = 0
with open("../keywordProcess/directoryStore/paragraph_output.json", "r",
          encoding="utf-8") as f:
    protocol_chapter = json.load(f)

with open("../keywordProcess/directoryStore/keywords_final.json", 'r', encoding='utf-8') as file:
    data = json.load(file)

specifyKeywords = data['specify']
modalKeywords = data['modal']
comparativeKeywords = data['comparative']

chapter_sentence_dict = {}
for heading, content in protocol_chapter.items():
    sentences = [s.strip() for s in re.split(r'(?<=[.!?])\s+', content) if s.strip()]
    chapter_sentence_dict[heading] = sentences

filtered_sentences = {}
text_output = []

df = pd.DataFrame(columns=["Heading", "Sentence", "Is_Matched"])

for heading, sentences in chapter_sentence_dict.items():
    matched_sentences = []
    count += len(sentences)
    for sentence in sentences:
        specify_matches = [word for word in specifyKeywords if word in sentence]
        modal_matches = [word for word in modalKeywords if word in sentence]
        comparative_matches = [word for word in comparativeKeywords if word in sentence]
        is_matched = False
        
        if len(specify_matches) >= 2 or (
                len(specify_matches) >= 1 and (len(modal_matches) >= 1 or len(comparative_matches) >= 1)):
            cnt += 1
            matched_sentences.append(sentence)
            is_matched = True
            text_output.append(f"Heading: {heading}\n")
            text_output.append(f"Sentence: {sentence}\n")
            text_output.append(f"Matched specifyKeywords: {', '.join(specify_matches)}\n")
            text_output.append(f"Matched modalKeywords: {', '.join(modal_matches)}\n")
            text_output.append(f"Matched comparativeKeywords: {', '.join(comparative_matches)}\n")
            text_output.append("-" * 50 + "\n")

        new_row = pd.DataFrame({
            "Heading": [heading],
            "Sentence": [sentence],
            "Is_Matched": [is_matched]
        })
        df = pd.concat([df, new_row], ignore_index=True)

    if matched_sentences:
        filtered_sentences[heading] = matched_sentences

with open("directoryStore/filtered_sentences.json", "w", encoding="utf-8") as json_file:
    json.dump(filtered_sentences, json_file, ensure_ascii=False, indent=4)

with open("directoryStore/matched_sentences.txt", "w", encoding="utf-8") as txt_file:
    txt_file.writelines(text_output)

df.to_excel("directoryStore/filtered_sentences.xlsx", index=False, engine='openpyxl')

print(count)
print(cnt)