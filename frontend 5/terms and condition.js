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

export default function Terms() {
  const navigation = useNavigation();
  const [termsContent, setTermsContent] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTerms();
  }, []);

  const fetchTerms = async () => {
    try {
      const response = await fetch('http://localhost:8000/terms'); // Adjust URL as needed
      const data = await response.json();
      setTermsContent(data);
    } catch (error) {
      console.error('Failed to fetch terms:', error);
      // Fallback to static content if API fails
      setTermsContent({
        title: "Terms & Conditions",
        sections: [
          {
            title: "1. Acceptance",
            content: "By using VerbX and the Ivish AI Assistant, you agree to these Terms. If you do not agree, do not use the app."
          },
          {
            title: "2. License to Use",
            content: "You are granted a non-exclusive, non-transferable license to use the app for personal, educational, and professional use."
          },
          {
            title: "3. User Responsibilities",
            content: "• Do not misuse the assistant for illegal, abusive, or harmful purposes.\n• Do not impersonate others using the voice biometric system.\n• Do not attempt to reverse-engineer models or access protected routes.\n• You are responsible for ensuring your local laws permit use of translation or AI tools."
          },
          {
            title: "4. AI Limitations",
            content: "• Ivish may occasionally generate inaccurate translations or emotional interpretations.\n• Content suggestions are not professional advice."
          },
          {
            title: "5. Memory and Consent",
            content: "• By default, all interactions are session-based.\n• Persistent memory requires your explicit consent.\n• You may opt out at any time via the app settings."
          },
          {
            title: "6. Subscription and Billing",
            content: "• Some features (like real-time voice calls, offline packs) may require a paid plan.\n• Subscription details, pricing, and usage limits are available at Settings > Plans."
          },
          {
            title: "7. Termination",
            content: "VerbX may suspend or terminate accounts for violations including abuse, tampering, or multiple failed voice authentication attempts."
          },
          {
            title: "8. Modifications",
            content: "We reserve the right to modify these Terms. You’ll be notified in advance with the option to decline and uninstall."
          },
        ]
      });
    } finally {
      setLoading(false);
    }
  };

  const renderSectionContent = (content) => {
    return content.split('\n').map((line, index) => {
      if (line.trim().startsWith('•')) {
        return <Text key={index} style={styles.bullet}>{line}</Text>;
      } else {
        return <Text key={index} style={styles.paragraph}>{line}</Text>;
      }
    });
  };

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
        <Text style={styles.title}>Terms & Conditions</Text>
      </View>

      {/* Content */}
      <ScrollView contentContainerStyle={styles.content}>
        {loading ? (
          <Text>Loading...</Text>
        ) : termsContent && termsContent.sections ? (
          termsContent.sections.map((section, index) => (
            <View key={index}>
              <Text style={styles.sectionTitle}>{section.title}</Text>
              {renderSectionContent(section.content)}
            </View>
          ))
        ) : (
          <Text>Error loading terms</Text>
        )}

        {/* Agree Button */}
        <TouchableOpacity style={styles.button}>
          <Text style={styles.buttonText}>I Agree</Text>
        </TouchableOpacity>

        {/* Download Link */}
        <View style={styles.linkContainer}>
          <Text style={styles.linkText}>Download T&C as (PDF)</Text>
          <Svg width={13} height={13} viewBox="0 0 13 13" fill="none">
            <Path
              d="M1.0555 9.5699V10.931C1.0555 11.292 1.1989 11.6382 1.4542 11.8935C1.7095 12.1487 2.0557 12.2921 2.4167 12.2921H10.5833C10.9443 12.2921 11.2905 12.1487 11.5458 11.8935C11.8011 11.6382 11.9445 11.292 11.9445 10.931V9.5699M3.0972 5.4866L6.5 8.8893M6.5 8.8893L9.9028 5.4866M6.5 8.8893V0.7227"
              stroke="black"
              strokeWidth="1.36"
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
    paddingTop: 50,
    paddingHorizontal: 20,
    paddingBottom: 4,
    marginLeft:10,
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
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#0C0D11',
    marginTop: 24,
    marginBottom: 12,
    fontFamily: 'Poppins',
  },
  paragraph: {
    fontSize: 14,
    lineHeight: 20,
    color: '#2C2C2C',
    marginBottom: 24,
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
    color: '#F6F6F8',
    fontSize: 17,
    fontWeight: '700',
    fontFamily: 'Poppins',
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
