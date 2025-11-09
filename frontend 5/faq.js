import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  Platform,
} from 'react-native';
import Svg, { Path } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { getFAQs } from './api';

const FAQItem = ({ id, question, answer, isOpen, onToggle }) => (
  <View style={styles.faqItem}>
    <TouchableOpacity style={styles.faqHeader} onPress={() => onToggle(id)}>
      <Text style={styles.faqQuestion}>{`${id}. ${question}`}</Text>
      <Svg
        width={15}
        height={8}
        viewBox="0 0 15 8"
        fill="none"
        style={isOpen ? styles.chevronUp : styles.chevronDown}
      >
        <Path
          d={isOpen ? "M1.5 7L7.5 1L13.5 7" : "M1.5 1L7.5 7L13.5 1"}
          stroke="#0E0E0E"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </Svg>
    </TouchableOpacity>
    {isOpen && <Text style={styles.faqAnswer}>{answer}</Text>}
  </View>
);

export default function FAQ() {
  const navigation = useNavigation();
  const [openId, setOpenId] = useState(null);
  const [faqs, setFaqs] = useState([]);

  useEffect(() => {
    const fetchFAQs = async () => {
      try {
        const data = await getFAQs();
        setFaqs(data);
      } catch (error) {
        console.error('Failed to fetch FAQs:', error);
        // Fallback to static FAQs if API fails
        setFaqs([
          {
            id: 1,
            question: 'What is VerbX and Ivish?',
            answer: 'VerbX is your personal language companion — it helps you talk, translate, learn, and connect in multiple languages.\nIvish is the smart assistant inside VerbX — like a friend who understands your voice, emotion, and language.',
          },
          {
            id: 2,
            question: 'Do I need to speak in English to use Ivish?',
            answer: 'Nope! Ivish understands many languages including Hindi, Tamil, Telugu, Kannada, Bengali, and more.\nYou can speak in your native language or even mix them — Ivish will get it.',
          },
          {
            id: 3,
            question: 'Is it safe to use?',
            answer: 'Yes. Everything you say is encrypted. Your voiceprints are secure, and you can delete your data anytime. We don’t track or store anything without your consent.',
          },
          {
            id: 4,
            question: 'Does Ivish work offline?',
            answer: 'Yes! You can use voice-to-text, translation, and more even without internet — just download the Offline Pack in settings.',
          },
          {
            id: 5,
            question: 'How do I start a voice chat with Ivish?',
            answer: 'Just say “Hey Ivish” or tap the mic icon. Ivish will listen and reply instantly.',
          },
          {
            id: 6,
            question: 'Can I type instead of speaking?',
            answer: 'Yes! Use the Live Chat feature to type messages to Ivish if you’re in a quiet place or prefer texting.',
          },
          {
            id: 7,
            question: 'Why is Ivish repeating what I said?',
            answer: 'That’s normal — Ivish might echo short phrases to confirm understanding. You can turn this off in Settings → Voice Preferences.',
          },
          {
            id: 8,
            question: 'How do I save a useful phrase or translation?',
            answer: 'Just say “Save this” or tap the bookmark icon after any message. You’ll find your saved phrases under “My Phrasebook.”',
          },
          {
            id: 9,
            question: 'I think Ivish misunderstood me. What can I do?',
            answer: 'No worries. You can:\n• Tap the message and choose “Rephrase” or “Translate again”\n• Or say “That’s not what I meant”\nIvish learns and improves over time.',
          },
          {
            id: 10,
            question: 'Can I use this during calls or video chats?',
            answer: 'Yes! Ivish can add live subtitles or translate voice during calls — just enable “Call Mode” in the settings.',
          },
          {
            id: 11,
            question: 'How do I change languages?',
            answer: 'Tap the language dropdown in the chat screen, or just say “Speak in Tamil from now” or “Translate to Hindi please.”',
          },
          {
            id: 12,
            question: 'What if I forget a word or phrase?',
            answer: 'Just ask! Say “How do I say ‘Good evening’ in Bengali?”\nIvish will show and pronounce it for you.',
          },
          {
            id: 13,
            question: 'Does Ivish help with pronunciation?',
            answer: 'Yes! You’ll get instant feedback on grammar and accent. There’s even a “Practice Mode” if you want to speak back and get corrected.',
          },
          {
            id: 14,
            question: 'Is there a way to learn languages inside the app?',
            answer: 'Absolutely. Go to the Learning Hub — you’ll find short lessons, quizzes, and daily challenges. It’s fun, fast, and personalized.',
          },
          {
            id: 15,
            question: 'Can I delete everything Ivish remembers about me?',
            answer: 'Yes. Go to Settings → Privacy & Security → Wipe Memory. Your data will be deleted instantly. We respect your privacy 100%.',
          },
          {
            id: 16,
            question: 'How do I report a bug or get help?',
            answer: 'Go to Settings → Help & Support → Report an Issue.\nYou can also drop a message in the Live Support Chat, and our team will get back ASAP.',
          },
        ]);
      }
    };
    fetchFAQs();
  }, []);

  const toggleFAQ = (id) => setOpenId(openId === id ? null : id);

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
            <Path
              d="M7 1L1 7L7 13"
              stroke="black"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </TouchableOpacity>
        <Text style={styles.headerTitle}>FAQ’s</Text>
        <View style={{ width: 24 }} />
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {faqs.map((item) => (
          <FAQItem
            key={item.id}
            id={item.id}
            question={item.question}
            answer={item.answer}
            isOpen={openId === item.id}
            onToggle={toggleFAQ}
          />
        ))}
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingTop:  39,
    backgroundColor: '#FFF',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 12,
    columnGap: 25, // Added gap here
    marginLeft:9,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
    fontFamily: 'Poppins',
  },
  scrollContent: {
    padding: 20,
    paddingBottom: 40,
  },
  faqItem: {
    marginBottom: 12,
    borderWidth: 1,
    borderColor: '#2C2C2C',
    borderRadius: 12,
    backgroundColor: '#FFF',
  },
  faqHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 14,
  },
  faqQuestion: {
    fontSize: 14,
    fontWeight: '500',
    color: '#0E0E0E',
    fontFamily: 'Poppins',
    flex: 1,
  },
  chevronDown: {
    transform: [{ rotate: '-90deg' }],
  },
  chevronUp: {
    transform: [{ rotate: '0deg' }],
  },
  faqAnswer: {
    paddingHorizontal: 16,
    paddingBottom: 14,
    fontSize: 12,
    lineHeight: 18,
    color: '#0E0E0E',
    fontFamily: 'Poppins',
  },
});
 