import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  Image,
  StatusBar,
  Alert,
} from 'react-native';
import {
  ArrowLeft,
  Volume2,
  Star,
  Users,
  Mic
} from 'lucide-react-native';

const PRIMARY_PERANO = '#BFC5F5';

export default function TranslationScreen() {
  const [inputText, setInputText] = useState('');
  const [translatedText, setTranslatedText] = useState('पाठ यहाँ लिखें');
  const [isLoading, setIsLoading] = useState(false);

  const translateText = async (text) => {
    if (!text.trim()) {
      setTranslatedText('पाठ यहाँ लिखें');
      return;
    }

    setIsLoading(true);

    try {
      // Try backend API first
      const response = await fetch('http://localhost:8000/translate/text', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text: text,
          src_lang: 'en',
          tgt_lang: 'hi',
          session_token: 'dummy_session_token_64_chars_long_for_testing_purposes_only_1234',
          user_token: 'dummy_user_token',
          zk_proof: 'dummy_zk_proof_128_chars_long_for_testing_purposes_only_and_should_be_replaced_with_real_proof_in_production_environment_and_this_needs_to_be_at_least_128_characters_long'
        }),
      });

      if (response.ok) {
        const data = await response.json();
        setTranslatedText(data.translated_text);
      } else {
        throw new Error('API call failed');
      }
    } catch (error) {
      console.log('Backend translation failed, using mock:', error);
      // Fallback to mock translation
      if (text.toLowerCase().includes('hello')) {
        setTranslatedText('नमस्ते');
      } else if (text.toLowerCase().includes('how are you')) {
        setTranslatedText('आप कैसे हैं?');
      } else {
        setTranslatedText('पाठ यहाँ लिखें');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: PRIMARY_PERANO }]}>
      <StatusBar barStyle="dark-content" backgroundColor={PRIMARY_PERANO} />
      
      {/* Header */}
      <View style={[styles.header, { backgroundColor: PRIMARY_PERANO }]}> 
        <TouchableOpacity style={styles.backButton}>
          <ArrowLeft size={24} color="#000" />
        </TouchableOpacity>
        <View style={styles.headerRow}>
          <Text style={styles.headerTitle}>Speak now</Text>
          <View style={styles.headerRight}>
            <TouchableOpacity style={styles.speakerButton}>
              <Volume2 size={20} color="#666" />
            </TouchableOpacity>
            <TouchableOpacity style={styles.profileButton}>
              <Image
                source={{ uri: 'https://images.pexels.com/photos/1040880/pexels-photo-1040880.jpeg?auto=compress&cs=tinysrgb&w=50&h=50&fit=crop' }}
                style={styles.profileImage}
              />
            </TouchableOpacity>
          </View>
        </View>
      </View>

      {/* Main Content */}
      <View style={styles.mainContent}>
        <View style={styles.textInputStarRow}>
          <TextInput
            style={styles.textInput}
            placeholder="Enter text here"
            placeholderTextColor="#666"
            value={inputText}
            onChangeText={(text) => {
              setInputText(text);
              translateText(text);
            }}
            multiline
          />
          <TouchableOpacity style={styles.starButton}>
            <Star size={24} color="#666" />
          </TouchableOpacity>
        </View>
        
        <View style={styles.translatedTextContainer}>
          <Text style={styles.translatedText}>
            {isLoading ? 'Translating...' : translatedText}
          </Text>
        </View>
      </View>

      {/* Footer */}
      <View style={styles.footer}>
        <View style={styles.actionButtons}>
          <TouchableOpacity style={styles.actionButton}>
            <Users size={22} color="#fff" />
          </TouchableOpacity>
          
          <TouchableOpacity style={[styles.actionButton, styles.micButton]}>
            <Mic size={28} color="#fff" />
          </TouchableOpacity>
          
          <TouchableOpacity style={styles.actionButton}>
            <Image
              source={require('./assets/ivish.png')}
              style={styles.ivishLogo}
              resizeMode="contain"
            />
          </TouchableOpacity>
        </View>
        
        <View style={styles.languageSelector}>
          <View style={styles.languageBox}>
            <Text style={styles.languageText}>Hindi</Text>
          </View>
          <Image
            source={require('./assets/swap.png')}
            style={styles.translationArrowLogo}
            resizeMode="contain"
          />
          <View style={styles.languageBox}>
            <Text style={styles.languageText}>English</Text>
          </View>
        </View>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    flexDirection: 'column',
    paddingHorizontal: 16,
    paddingTop: 12,
    paddingBottom: 0,
  },
  headerTopRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  backButton: {
    width: 40,
    height: 40,
    aspectRatio: 1,
    marginLeft: 0,
    marginTop: 32,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'transparent',
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: 8,
  },
  headerTitle: {
    color: '#4A4A4A',
    fontFamily: 'Poppins',
    fontSize: 20,
    fontWeight: '500',
    lineHeight: 26,
    textAlign: 'left',
    marginLeft: 10,
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 25,
  },
  speakerButton: {
    padding: 4,
  },
  profileButton: {
    width: 32,
    height: 32,
    borderRadius: 16,
    overflow: 'hidden',
  },
  profileImage: {
    width: '100%',
    height: '100%',
  },
  mainContent: {
    flex: 1,
    paddingHorizontal: 16,
    paddingTop: 20,
  },
  textInputStarRow: {
    flexDirection: 'row',
    alignItems: 'center',
    alignSelf: 'stretch',
    marginTop: 24,
    marginBottom: 16,
    width: '100%',
    marginLeft: 4,
  },
  textInput: {
    flex: 1,
    alignSelf: 'stretch',
    color: '#2A2A2A',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 40,
    fontStyle: 'normal',
    fontWeight: 'bold',
    lineHeight: 52,
    backgroundColor: 'transparent',
    borderWidth: 0,
    paddingVertical: 0,
    minHeight: 52,
  },
  starButton: {
    justifyContent: 'center',
    alignItems: 'center',
    alignSelf: 'flex-end',
    padding: 8,
  },
  translatedTextContainer: {
    marginTop: 8,
    marginLeft: 10,
  },
  translatedText: {
    alignSelf: 'stretch',
    color: '#5E5E5E',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 30,
    fontStyle: 'normal',
    fontWeight: '500',
    lineHeight: 39,
  },
  footer: {
    backgroundColor: '#000',
    paddingVertical: 20,
    paddingHorizontal: 16,
    borderTopLeftRadius: 20,
    borderTopRightRadius: 20,
  },
  actionButtons: {
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 16,
    gap: 40,
  },
  actionButton: {
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: '#333',
    justifyContent: 'center',
    alignItems: 'center',
  },
  micButton: {
    backgroundColor: '#FF6B35',
    width: 70,
    height: 70,
    borderRadius: 35,
  },
  ivishLogo: {
    width: '100%',
    height: '100%',
    borderRadius: 28,
    margin: 0,
    padding: 0,
  },
  languageSelector: {
    flexDirection: 'row',
    height: 60,
    paddingHorizontal: 20,
    justifyContent: 'center',
    alignItems: 'center',
    gap: 16,
    alignSelf: 'stretch',
    borderRadius: 20,
  },
  languageText: {
    color: '#fff',
    fontSize: 25,
    fontWeight: '500',
  },
  translationArrowLogo: {
    width: 36,
    height: 24,
    tintColor: '#fff',
    marginHorizontal: 12,
  },
  languageBox: {
    backgroundColor: '#232323',
    borderRadius: 20,
    paddingVertical: 10,
    paddingHorizontal: 32,
    justifyContent: 'center',
    alignItems: 'center',
    minWidth: 120,
  },
});