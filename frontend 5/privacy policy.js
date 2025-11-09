import React from 'react';
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

export default function Policy() {
  const navigation = useNavigation();

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Svg width={8} height={24} viewBox="0 0 8 14" fill="none">
            <Path
              d="M7 1L1 7L7 13"
              stroke="#2C2C2C"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </TouchableOpacity>
        <Text style={styles.title}>Privacy Policy</Text>
      </View>

      {/* Content */}
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.paragraph}>
          This Privacy Policy explains how VerbX (“we”, “our”, or “us”) collects, uses, protects, and 
          deletes personal data when you use the Ivish AI Assistant and related features.
        </Text>

        <Text style={styles.heading}>What We Collect:</Text>
        <Text style={styles.bullet}>
          • Voice Data: Includes speech input, tone, and optional voiceprints for authentication.
        </Text>
        <Text style={styles.bullet}>
          • Text Data: Chat content, phrasebooks, translations, and corrections you provide.
        </Text>
        <Text style={styles.bullet}>
          • Emotion Metadata: Inferred emotional tone to personalize responses.
        </Text>
        <Text style={styles.bullet}>
          • Device Info: Basic diagnostics (mic status, OS version) for app performance.
        </Text>
        <Text style={styles.bullet}>
          • Session Logs: Temporary data for improving experience (deleted post-session).
        </Text>
        <Text style={styles.bullet}>
          • Consent Logs: Consent choices and legal agreements (stored with blockchain hash).
        </Text>

        <Text style={styles.heading}>Why We Collect It:</Text>
        <Text style={styles.bullet}>
          • To provide real-time speech-to-text (STT), translations, and emotion-aware responses.
        </Text>
        <Text style={styles.bullet}>
          • To personalize learning experiences, responses, and tone.
        </Text>
        <Text style={styles.bullet}>
          • To enhance security through biometric voice authentication.
        </Text>
        <Text style={styles.bullet}>
          • To meet regulatory compliance and safety (GDPR, HIPAA).
        </Text>

        <Text style={styles.heading}>Data Retention:</Text>
        <Text style={styles.bullet}>
          • Voiceprints: One-way encrypted; never reversible.
        </Text>
        <Text style={styles.bullet}>
          • Session Data: Deleted automatically after logout or timeout.
        </Text>
        <Text style={styles.bullet}>
          • Phrase Memory: Stored locally or with consent in Redis (90-day TTL).
        </Text>
        <Text style={styles.bullet}>
          • Audit Trails: Stored immutably via blockchain logs for compliance.
        </Text>
        <Text style={styles.bullet}>
          • Diagnostics: Retained temporarily for debugging, anonymized.
        </Text>

        <Text style={styles.heading}>Your Rights:</Text>
        <Text style={styles.bullet}>
          • Access or delete your stored data (see “Memory Dashboard” in settings).
        </Text>
        <Text style={styles.bullet}>
          • Withdraw consent at any time via the Consent Center.
        </Text>
        <Text style={styles.bullet}>
          • Use the app without persistent memory (session-only mode available).
        </Text>
        <Text style={styles.bullet}>
          • Export or wipe your stored content in compliance with GDPR Article 17 (Right to Erasure).
        </Text>

        <Text style={styles.heading}>Offline & Edge Processing:</Text>
        <Text style={styles.paragraph}>
          When using offline mode, your voice and text are processed locally (no server upload).
          Models like Whisper.cpp and Sarvam operate entirely on your device.
        </Text>

        <Text style={styles.heading}>Security Measures:</Text>
        <Text style={styles.bullet}>
          • End-to-end encryption (AES-256 + RSA)
        </Text>
        <Text style={styles.bullet}>
          • Zero-Knowledge Proof authentication
        </Text>
        <Text style={styles.bullet}>
          • Voice biometric spoof detection
        </Text>
        <Text style={styles.bullet}>
          • Anomaly detection and endpoint isolation on breach attempts
        </Text>

        <Text style={styles.heading}>Changes to Policy:</Text>
        <Text style={styles.paragraph}>
          We may update this policy periodically. You'll be notified in-app with an option to review changes.
        </Text>

        {/* Agree Button */}
        <TouchableOpacity style={styles.button}>
          <Text style={styles.buttonText}>Agree & Continue</Text>
        </TouchableOpacity>

        {/* Full Policy Link */}
        <View style={styles.linkContainer}>
          <Text style={styles.linkText}>Read our full privacy policy</Text>
          <Svg width={15} height={15} viewBox="0 0 15 15" fill="none">
            <Path
              d="M7.5 2.667H2.833C2.4207 2.667 2.025 2.8309 1.7333 3.1226C1.4416 3.4143 1.2777 3.81 1.2777 4.2226V12.0003C1.2777 12.413 1.4416 12.8087 1.7333 13.1004C2.025 13.3921 2.4207 13.556 2.833 13.556H10.611C11.0233 13.556 11.419 13.3921 11.7107 13.1004C12.0024 12.8087 12.1663 12.413 12.1663 12.0003V7.3336M6.7222 8.111L13.7222 1.111L13.7222 5M13.7222 1.111H9.8333"
              stroke="black"
              strokeWidth="1.5556"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </Svg>
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#FFF',
   
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 25,
    paddingHorizontal: 20,
    paddingBottom: 4,
    marginLeft:9,
    paddingTop: 50 ,
  },
  title: {
    fontSize: 20,
    fontWeight: '500',
    fontFamily: 'Poppins',
    color: '#0C0D11',
    lineHeight: 26,
  },
  content: {
    paddingHorizontal: 20,
    paddingBottom: 40,
    paddingTop: 0,
  },
  paragraph: {
    fontSize: 14,
    lineHeight: 20,
    color: '#2C2C2C',
    marginBottom: 24,
    fontFamily: 'Poppins',
  },
  heading: {
    fontSize: 16,
    fontWeight: '500',
    color: '#0C0D11',
    marginBottom: 12,
    fontFamily: 'Poppins',
  },
  bullet: {
    fontSize: 14,
    lineHeight: 20,
    color: '#2C2C2C',
    marginBottom: 8,
    fontFamily: 'Poppins',
  },
  button: {
    marginTop: 32,
    backgroundColor: '#0C0D11',
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonText: {
    color: '#FFF',
    fontSize: 17,
    fontWeight: '700',
    fontFamily: 'Cabinet Grotesk',
  },
  linkContainer: {
    flexDirection: 'row',
    marginTop: 12,
    alignItems: 'center',
    justifyContent: 'center',
  },
  linkText: {
    fontSize: 12,
    color: '#2C2C2C',
    fontFamily: 'Poppins',
    marginRight: 8,
  },
});