from dotenv import load_dotenv
import os
import json
import pandas as pd
from datetime import date
from crewai import LLM
load_dotenv()  # Loads from .env

API_KEY = os.getenv("OPENAI_API_KEY")

def aiScanner(path,entropy,isSuspicious,todaysDate):
    try:
        with open('firebase_service_sales_first.json') as f:
            vertex_credentials_json = json.dumps(json.load(f))
 
        llm = LLM(
            model="vertex_ai/gemini-2.0-flash-001",
            temperature=0.1,
            vertex_credentials=vertex_credentials_json,
            max_tokens=8192
        )

        prompt = f"""You are a cybersecurity validation system.

    Each row below represents a file that has been flagged as suspicious by a heuristic malware scanner. Your job is to decide if the flagged file is a FALSE POSITIVE or a TRUE POSITIVE.

    Use ONLY the following columns for analysis:
    1. File Path - indicates where the file exists on the system.
    2. Entropy - numerical value (typically 0-8); values above 7.0 might indicate obfuscation.
    3. isSuspicious - indicates whether the file was flagged by the heuristic engine.

    Return your result for each file in the following format:
    <file_path> → <FALSE POSITIVE or TRUE POSITIVE>  
    (Reason: <short justification>)

    Rules to follow:
    - Do NOT invent any file content or assume what the file does unless obvious from the path.
    - If entropy is high (>7.0) and the path is in `/tmp`, `/var/tmp`, or a non-standard directory, it is likely a TRUE POSITIVE.
    - If entropy is moderate (<6.5) and the file is in a common path like `/usr/bin`, `/lib`, or `/etc`, it is likely a FALSE POSITIVE.
    - Do not hallucinate strings, payloads, or external behaviors. Work only with provided features.
    - Do not give explanation just provide whether the given path is FALSE POSITIVE/ TRUE POSITIVE
    Now evaluate this file:

    - Path: {path}
    - Entropy: {entropy}
    - isSuspicious: {isSuspicious}
    """
        completion = llm.call(prompt)
        with open(f"{todaysDate}.csv","a")as file:
            file.write(path)
            file.write(",")
            file.write(str(entropy))
            file.write(",")
            file.write(isSuspicious)
            file.write(",")
            file.write(completion)
            file.write("\n")

    except Exception as e:
        print("Exception occured in AIScanner: "+str(e))

def main(filepath):
    try:
        data = pd.read_csv(filepath)
        df = pd.DataFrame(data)
        jsonData = json.loads(df.to_json(orient='records'))
        today = date.today()
        todaysDate = today.isoformat()
        with open(f"{todaysDate}.csv","w")as file:
            file.write("path")
            file.write(",")
            file.write("entropy")
            file.write(",")
            file.write("isSuspicious")
            file.write(",")
            file.write("scanStatus")
            file.write("\n")
        for data in jsonData:
            aiScanner(data['path'],data['entropy'],data['isSuspicious'],todaysDate)
    except Exception as e:
        print("Exception occured in AIScanner.main method: "+str(e))

main("/home/sandeep/cppTutorials/Antivirus/Heuristic Scanner/paths.csv")