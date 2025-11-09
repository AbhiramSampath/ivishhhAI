import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
from collections import defaultdict
import asyncio
import os
import json
import sys

# Core Imports
from ai_models.whisper.whisper_handler import transcribe_audio

from ai_models.emotion.emotion_handler import detect_emotion


from backend.app.utils.logger import log_event
from backend.app.services.feedback_service import update_learning_score
from backend.app.utils.security import secure_hash
from ai_models.ivish.ivish_memory import format_context
from self_learning.autocoder import AutoCoder

# Assuming a placeholder for test rubrics, as no config file was provided
TEST_RUBRICS = {
    "IELTS": {"coherence": 0.25, "lexical_resource": 0.25, "grammar": 0.25, "pronunciation": 0.25},
    "CEFR": {"accuracy": 0.5, "fluency": 0.5},
    "TOEFL": {"integrated": 0.5, "independent": 0.5},
    "CUSTOM": {"custom_param": 1.0}
}


# Initialize autocoder for adaptive feedback
autocoder = AutoCoder()

# Scoring Constants
MIN_RESPONSE_LENGTH = 20  # Minimum words for valid response
MAX_TEST_DURATION = 3600  # 1 hour max test time
SUPPORTED_TESTS = ["CEFR", "IELTS", "TOEFL", "CUSTOM"]
SUPPORTED_MODES = ["speaking", "writing", "reading", "listening"]

class TestSession:
    """
    Encapsulates a test session with metadata, scoring, and feedback.
    Supports both voice and text input with multi-modal evaluation.
    """

    def __init__(self, user_id: str, test_type: str = "CEFR", mode: str = "writing"):
        self.session_id = str(uuid.uuid4())
        self.user_id = user_id
        self.test_type = test_type
        self.mode = mode
        self.start_time = datetime.now(timezone.utc)
        self.completed = False
        self.results = defaultdict(list)
        self.feedback = []

    def validate_input(self, response: str) -> bool:
        """Ensure minimum quality and length for scoring"""
        if len(response.split()) < MIN_RESPONSE_LENGTH:
            log_event(f"TEST: Short response from {self.user_id}", level="WARNING")
            return False
        return True

    def calculate_duration(self) -> float:
        """Calculate time taken for test"""
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()

    def finalize(self) -> Dict[str, Any]:
        """Finalize test session with final results"""
        self.completed = True
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "test_type": self.test_type,
            "mode": self.mode,
            "duration": self.calculate_duration(),
            "timestamp": self.start_time.isoformat(),
            "results": dict(self.results),
            "feedback": self.feedback
        }

    def add_result(self, key: str, value: Any):
        """Add result to session"""
        self.results[key].append(value)

    def add_feedback(self, text: str):
        """Add feedback to session"""
        self.feedback.append(text)

    def __str__(self):
        return f"TestSession({self.session_id}, {self.user_id}, {self.test_type}, {self.mode})"


def run_test(user_id: str, test_input: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for test execution.
    Supports voice and text input with multi-modal scoring and feedback.
    """
    session = TestSession(
        user_id=user_id,
        test_type=test_input.get("test_type", "CEFR"),
        mode=test_input["mode"]
    )

    try:
        if test_input["mode"] == "speaking":
            transcribed = transcribe_audio(test_input["input"])
            if not session.validate_input(transcribed):
                session.add_result("error", "Short response")
                return session.finalize()

            score, rubric = score_response(transcribed, test_input.get("test_type", "IELTS"))
            emotion = detect_emotion(transcribed)

            session.add_result("transcript", transcribed)
            session.add_result("score", score)
            session.add_result("rubric", rubric)
            session.add_result("emotion", emotion)
         

        elif test_input["mode"] == "writing":
            response = test_input["input"]
            if not session.validate_input(response):
                session.add_result("error", "Short response")
                return session.finalize()

       
            score, rubric = score_response(response, test_input.get("test_type", "IELTS"))
            

            session.add_result("original", response)
          
            session.add_result("score", score)
            session.add_result("rubric", rubric)
        

        elif test_input["mode"] == "reading":
            # Placeholder for future reading comprehension module
            pass

        elif test_input["mode"] == "listening":
            # Placeholder for future listening comprehension module
            pass

        else:
            session.add_result("error", "Unsupported test mode")
            return session.finalize()

        # Update user memory and learning score
        if session.results.get("score"):
            update_learning_score(user_id, session.results["score"][-1])

        # Log test completion
        log_event(f"TEST_COMPLETED: {session.session_id} by {user_id}")

        # Auto-evolve feedback system
        asyncio.create_task(autocoder.learn_from_test(session.finalize()))

        return session.finalize()

    except Exception as e:
        log_event(f"TEST: Error in test execution: {str(e)}", level="ERROR")
        session.add_result("error", str(e))
        return session.finalize()


def score_response(text: str, test_type: str = "IELTS") -> Tuple[float, Dict[str, float]]:
    """
    Evaluate grammar, coherence, and lexical richness to assign a CEFR/IELTS/TOEFL band.
    Uses configurable rubrics for different test types.
    """
    rubric = TEST_RUBRICS.get(test_type, TEST_RUBRICS["IELTS"])

   


def generate_report(user_id: str, result: Dict[str, Any]) -> str:
    """
    Generate a textual summary of the test result.
    Includes scores, feedback, and suggestions.
    """
    try:
        report = f"""
        🔍 Test ID: {result['session_id']}
        📚 Type: {result['test_type']} - {result['mode'].capitalize()}
        📊 Score: {result['results']['score'][-1]}
        🎭 Emotion: {result['results'].get('emotion', ['neutral'])[-1]}
        📝 Feedback: {result['feedback'][-1] if result['feedback'] else 'No feedback'}
        ⏰ Time: {result['timestamp']}
        """
        return report.strip()
    except Exception as e:
        log_event(f"REPORTING: Error in report generation: {str(e)}", level="WARNING")
        return "Error generating report"


def suggest_improvement(text: str) -> List[str]:
    """
    Provide vocabulary, structure, and coherence suggestions.
    Uses local LLM or GPT-based feedback generator.
    """


def evaluate_listening(audio_file: str) -> Dict[str, Any]:
    """Future module for listening comprehension evaluation"""
    return {"score": 7.0, "feedback": "Good comprehension"}


def evaluate_reading(text: str) -> Dict[str, Any]:
    """Future module for reading comprehension evaluation"""
    return {"score": 6.5, "feedback": "Average comprehension"}


# If run as a script, provide a simple CLI for testing
if __name__ == "__main__":
    print("=== VerbX Test Integration CLI ===")
    user_id = input("Enter user ID: ").strip()
    mode = input("Enter mode (speaking/writing): ").strip().lower()
    test_type = input("Enter test type (CEFR/IELTS/TOEFL/CUSTOM): ").strip().upper()
    if mode == "speaking":
        input_data = input("Enter path to audio file: ").strip()
    else:
        input_data = input("Enter your response: ").strip()

    test_input = {
        "mode": mode,
        "test_type": test_type,
        "input": input_data
    }

    # Since run_test is an async function now, we need to run it in an event loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    result = loop.run_until_complete(run_test(user_id, test_input))
    print("\n--- Test Result ---")
    print(json.dumps(result, indent=2))

    print("\n--- Test Report ---")
    print(generate_report(user_id, result))