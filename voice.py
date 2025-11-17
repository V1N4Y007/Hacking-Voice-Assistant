import pyttsx3
import speech_recognition as sr
import datetime

engine = pyttsx3.init('sapi5')
voices = engine.getProperty('voices')
engine.setProperty('voice', voices[1].id)

def speak(audio):
    engine.say(audio)
    engine.runAndWait()

def wishMe():
    hour = int(datetime.datetime.now().hour)
    if 0 <= hour < 12:
        speak("Good Morning!")
    elif 12 <= hour < 18:
        speak("Good Afternoon!")
    else:
        speak("Good Evening!")
    speak("I am HackSpeak. Please tell me how may I help you")

def takeCommand():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Adjusting for background noise... 🎙️ Please wait")
        r.adjust_for_ambient_noise(source, duration=1.5)
        r.pause_threshold = 0.8    # shorter pause = faster response
        r.energy_threshold = 400   # minimum volume required
        print("Listening now... 🎤")

        try:
            audio = r.listen(source, phrase_time_limit=15)
        except Exception as e:
            print("⚠️ Listening error:", e)
            return ""

    try:
        print("Recognizing...")
        query = r.recognize_google(audio, language='en-in')
        print(f"✅ You said: {query}")
        return query.lower()
    except sr.UnknownValueError:
        print("❌ Couldn’t understand your voice.")
        return ""
    except sr.RequestError:
        print("❌ Network issue with Google Speech API.")
        return ""
