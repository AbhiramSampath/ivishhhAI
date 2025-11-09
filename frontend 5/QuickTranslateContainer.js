import React, { useState, useRef } from 'react';
import { View, Text, StyleSheet, TextInput, TouchableOpacity, Modal, ScrollView } from 'react-native';
import { Svg, Path } from 'react-native-svg';
import { translateText } from './api';

const LANGUAGES = ['Hindi', 'English', 'Japanese', 'Spanish', 'French', 'German', 'Chinese'];

export default function QuickTranslateContainer() {
  const [text, setText] = useState('');
  const [translatedText, setTranslatedText] = useState('');
  const [isEditing, setIsEditing] = useState(false);
  const [fromLanguage, setFromLanguage] = useState('Hindi');
  const [toLanguage, setToLanguage] = useState('English');
  const [showLanguageModal, setShowLanguageModal] = useState(false);
  const [languageToChange, setLanguageToChange] = useState(null);
  const textInputRef = useRef(null);

  const handleTextPress = () => {
    setIsEditing(true);
    setTimeout(() => {
      if (textInputRef.current) {
        textInputRef.current.focus();
      }
    }, 100);
  };

  const handleTranslate = async () => {
    if (text.trim()) {
      try {
        const result = await translateText(text, fromLanguage.toLowerCase(), toLanguage.toLowerCase());
        setTranslatedText(result);
      } catch (error) {
        console.error('Translation failed:', error);
        setTranslatedText('Translation failed. Please try again.');
      }
    }
  };

  const handleSwapLanguages = () => {
    setFromLanguage(toLanguage);
    setToLanguage(fromLanguage);
  };

  const openLanguageModal = (languageType) => {
    setLanguageToChange(languageType);
    setShowLanguageModal(true);
  };

  const selectLanguage = (lang) => {
    if (languageToChange === 'from') {
      setFromLanguage(lang);
    } else {
      setToLanguage(lang);
    }
    setShowLanguageModal(false);
  };

  return (
    <View style={styles.card}>
      {/* Main content with horizontal padding */}
      <View style={styles.cardContent}>
        {/* Top Row: Title left, icons right */}
        <View style={styles.topRow}>
          <Text style={styles.title}>
            {isEditing ? 'Translating...' : 'Start Translating'}
          </Text>
          <View style={styles.iconsRow}>
            {/* Speaker icon */}
            <View style={styles.iconCircle}>
              <View style={styles.iconsDarkInactive}>
                <Svg width={21} height={18} viewBox="0 0 21 18" fill="none">
                  <Path d="M13 5C13.621 5.46574 14.125 6.06966 14.4721 6.76393C14.8193 7.45821 15 8.22377 15 9C15 9.77623 14.8193 10.5418 14.4721 11.2361C14.125 11.9303 13.621 12.5343 13 13M15.7 2C16.744 2.84365 17.586 3.91013 18.1645 5.12132C18.7429 6.33252 19.0432 7.65776 19.0432 9C19.0432 10.3422 18.7429 11.6675 18.1645 12.8787C17.586 14.0899 16.744 15.1563 15.7 16M4 12H2C1.73478 12 1.48043 11.8946 1.29289 11.7071C1.10536 11.5195 1 11.2652 1 11V6.99997C1 6.73476 1.10536 6.4804 1.29289 6.29287C1.48043 6.10533 1.73478 5.99997 2 5.99997H4L7.5 1.49997C7.5874 1.3302 7.73265 1.1973 7.90949 1.12526C8.08633 1.05323 8.2831 1.04683 8.46425 1.10722C8.6454 1.1676 8.79898 1.29078 8.89723 1.45451C8.99549 1.61824 9.03194 1.81171 9 1.99997V16C9.03194 16.1882 8.99549 16.3817 8.89723 16.5454C8.79898 16.7092 8.6454 16.8323 8.46425 16.8927C8.2831 16.9531 8.08633 16.9467 7.90949 16.8747C7.73265 16.8027 7.5874 16.6697 7.5 16.5L4 12Z" stroke="#787878" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </Svg>
              </View>
            </View>
            {/* User icon */}
            <View style={styles.iconCircle}>
              <View style={styles.iconsDarkInactive}>
                <Svg width={20} height={20} viewBox="0 0 20 20" fill="none">
                  <Path d="M1 19V17C1 15.9391 1.42143 14.9217 2.17157 14.1716C2.92172 13.4214 3.93913 13 5 13H9C10.0609 13 11.0783 13.4214 11.8284 14.1716C12.5786 14.9217 13 15.9391 13 17V19M14 1.13C14.8604 1.35031 15.623 1.85071 16.1676 2.55232C16.7122 3.25392 17.0078 4.11683 17.0078 5.005C17.0078 5.89318 16.7122 6.75608 16.1676 7.45769C15.623 8.1593 14.8604 8.6597 14 8.88M19 19V17C18.9949 16.1172 18.6979 15.2608 18.1553 14.5644C17.6126 13.868 16.8548 13.3707 16 13.15M3 5C3 6.06087 3.42143 7.07828 4.17157 7.82843C4.92172 8.57857 5.93913 9 7 9C8.06087 9 9.07828 8.57857 9.82843 7.82843C10.5786 7.07828 11 6.06087 11 5C11 3.93913 10.5786 2.92172 9.82843 2.17157C9.07828 1.42143 8.06087 1 7 1C5.93913 1 4.92172 1.42143 4.17157 2.17157C3.42143 2.92172 3 3.93913 3 5Z" stroke="#787878" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </Svg>
              </View>
            </View>
          </View>
        </View>
        {/* Main Text Area */}
        <TouchableOpacity onPress={handleTextPress} activeOpacity={1}>
          {isEditing ? (
            <TextInput
              ref={textInputRef}
              style={[styles.inputText, { borderWidth: 0, backgroundColor: 'transparent' }]}
              value={text}
              onChangeText={setText}
              placeholder="Enter Text Here"
              placeholderTextColor="#999999"
              autoFocus={true}
              onBlur={() => {
                setIsEditing(false);
                handleTranslate();
              }}
              multiline
              underlineColorAndroid="transparent"
              selectionColor="#2C2C2C"
              caretHidden={true}
            />
          ) : (
            <Text style={styles.inputText}>{text || 'Enter Text Here'}</Text>
          )}
        </TouchableOpacity>
        {/* Translated Text Area */}
        {translatedText ? (
          <View style={styles.translatedContainer}>
            <Text style={styles.translatedText}>{translatedText}</Text>
          </View>
        ) : null}
      </View>
      {/* Language Bar at the bottom, full width, no horizontal padding */}
      <View style={styles.languageBar}>
        <TouchableOpacity onPress={() => openLanguageModal('from')} style={styles.languageTouchable}>
          <Text style={styles.languageText}>{fromLanguage}</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={handleSwapLanguages} style={styles.arrowContainer}>
          <Svg width={35} height={9} viewBox="0 0 35 9" fill="none">
            <Path d="M1.94385 8.0042H32.0562L27.0982 1.54858" stroke="black" strokeWidth="2" strokeLinecap="square"/>
          </Svg>
          <Svg width={35} height={9} viewBox="0 0 35 9" fill="none">
            <Path d="M33.0562 0.995795H2.94385L7.90182 7.45142" stroke="black" strokeWidth="2" strokeLinecap="square"/>
          </Svg>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => openLanguageModal('to')} style={styles.languageTouchable}>
          <Text style={styles.languageText}>{toLanguage}</Text>
        </TouchableOpacity>
      </View>
      {/* Language Selection Modal */}
      <Modal
        visible={showLanguageModal}
        transparent={true}
        animationType="slide"
        onRequestClose={() => setShowLanguageModal(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <ScrollView>
              {LANGUAGES.map((lang, index) => (
                <TouchableOpacity
                  key={index}
                  style={styles.languageOption}
                  onPress={() => selectLanguage(lang)}
                >
                  <Text style={styles.languageOptionText}>{lang}</Text>
                </TouchableOpacity>
              ))}
            </ScrollView>
            <TouchableOpacity
              style={styles.closeButton}
              onPress={() => setShowLanguageModal(false)}
            >
              <Text style={styles.closeButtonText}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  card: {
    borderRadius: 20,
    backgroundColor: 'rgba(191, 197, 245, 1)',
    paddingTop: 14,
    paddingBottom: 0,
    overflow: 'hidden',
    minHeight: 365,
    justifyContent: 'flex-start',
  },
  cardContent: {
    paddingHorizontal: 20,
    paddingBottom: 0,
  },
  topRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 7,
  },
  title: {
    color: '#4A4A4A',
    fontFamily: 'Poppins',
    fontSize: 20,
    fontWeight: '500',
    lineHeight: 26,
    textAlign: 'left',
  },
  iconsRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  iconCircle: {
    width: 40,
    height: 40,
    borderRadius: 20,
    backgroundColor: '#F6F6F8',
    alignItems: 'center',
    justifyContent: 'center',
    marginLeft: 8,
  },
  iconsDarkInactive: {
    height: 24,
    width: 24,
    justifyContent: 'center',
    alignItems: 'center',
  },
  inputText: {
    color: '#2C2C2C',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 36,
    fontWeight: '500',
    lineHeight: 47,
    textAlign: 'left',
    marginTop: 8,
    marginBottom: 0,
    borderWidth: 0,
    backgroundColor: 'transparent',
  },
  languageBar: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#F6F6F8',
    borderBottomLeftRadius: 20,
    borderBottomRightRadius: 20,
    borderTopLeftRadius: 0,
    borderTopRightRadius: 0,
    height: 60,
    width: '100%',
    position: 'absolute',
    left: 0,
    right: 0,
    bottom: 0,
  },
  languageTouchable: {
    flex: 1,
  },
  languageText: {
    textAlign: 'center',
    color: '#000',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 24,
    fontWeight: '500',
    lineHeight: 31,
  },
  arrowContainer: {
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    width: 40,
  },
  modalOverlay: {
    flex: 1,
    justifyContent: 'center', 
    alignItems: 'center',
    backgroundColor: 'rgba(0,0,0,0.5)',
  },
  modalContent: {
    backgroundColor: 'white',
    borderRadius: 20,
    padding: 20,
    width: '80%',
    maxHeight: '60%',
  },
  languageOption: {
    padding: 15,
    borderBottomWidth: 1,
    borderBottomColor: '#eee',
  },
  languageOptionText: {
    fontSize: 18, 
    textAlign: 'center',
  },
  closeButton: {
    marginTop: 15,
    padding: 10,
    backgroundColor: '#FFA364',
    borderRadius: 10,
    alignItems: 'center',
  },
  closeButtonText: {
    color: 'white',
    fontWeight: 'bold',
  },
  translatedContainer: {
    marginTop: 20,
    padding: 15,
    backgroundColor: '#F6F6F8',
    borderRadius: 10,
  },
  translatedText: {
    color: '#2C2C2C',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 24,
    fontWeight: '500',
    lineHeight: 31,
    textAlign: 'left',
  },
});
