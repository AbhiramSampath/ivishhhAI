import React, { useState, useRef, useEffect } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  Pressable,
  Animated,
  Platform,
} from 'react-native';
import Icon from 'react-native-vector-icons/Ionicons';
import Slider from '@react-native-community/slider';
import { useNavigation } from '@react-navigation/native';
import { Svg, Path } from 'react-native-svg';
import { fetchLanguages, updateUserLanguage } from './api/index';

// Custom back arrow component with standard styling
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

// Reusable Dropdown component with animation
const Dropdown = ({ value, onSelect, options }) => {
  const [isOpen, setIsOpen] = useState(false);
  const animatedHeight = useRef(new Animated.Value(0)).current;
  const animatedOpacity = useRef(new Animated.Value(0)).current;

  useEffect(() => {
    if (isOpen) {
      Animated.timing(animatedHeight, {
        toValue: 80, // Approximate height for 2 options
        duration: 250,
        useNativeDriver: false, // Height animation requires useNativeDriver: false
      }).start();
      Animated.timing(animatedOpacity, {
        toValue: 1,
        duration: 250,
        useNativeDriver: false,
      }).start();
    } else {
      Animated.timing(animatedHeight, {
        toValue: 0,
        duration: 250,
        useNativeDriver: false,
      }).start();
      Animated.timing(animatedOpacity, {
        toValue: 0,
        duration: 250,
        useNativeDriver: false,
      }).start();
    }
  }, [isOpen, animatedHeight, animatedOpacity]);

  const handleSelect = (option) => {
    onSelect(option);
    setIsOpen(false);
  };

  const handleToggle = () => {
    setIsOpen(!isOpen);
  };

  return (
    <View style={styles.dropdownWrapper}>
      <TouchableOpacity
        onPress={handleToggle}
        style={[
          styles.dropdownButton,
          isOpen && styles.dropdownButtonOpen,
        ]}
      >
        <Text>{value}</Text>
        <Icon
          name={isOpen ? 'chevron-up-outline' : 'chevron-down-outline'}
          size={20}
          color="#000"
        />
      </TouchableOpacity>
      <Animated.View
        style={[
          styles.dropdownList,
          {
            height: animatedHeight,
            opacity: animatedOpacity,
          },
        ]}
      >
        {options.map((option, index) => (
          <TouchableOpacity
            key={index}
            style={[
              styles.dropdownOption,
              index === options.length - 1 && styles.lastDropdownOption,
              option === value && styles.selectedOption
            ]}
            onPress={() => handleSelect(option)}
          >
            <Text>{option}</Text>
          </TouchableOpacity>
        ))}
      </Animated.View>
    </View>
  );
};

const CustomToggleSwitch = ({ value, onValueChange }) => {
  const animatedValue = useRef(new Animated.Value(value ? 1 : 0)).current;

  useEffect(() => {
    Animated.timing(animatedValue, {
      toValue: value ? 1 : 0,
      duration: 200,
      useNativeDriver: true,
    }).start();
  }, [value, animatedValue]);

  const translateX = animatedValue.interpolate({
    inputRange: [0, 1],
    outputRange: [1.5, 38.25 - 20.25],
  });

  return (
    <Pressable
      style={[
        styles.customSwitchTrack,
        value && { backgroundColor: '#FFA364' },
      ]}
      onPress={() => onValueChange(!value)}
    >
      <Animated.View
        style={[styles.customSwitchThumb, { transform: [{ translateX }] }]}
      />
    </Pressable>
  );
};

const TranslationPreferencesScreen = () => {
  // Initialize the navigation hook
  const navigation = useNavigation();

  const [subtitleFontSize, setSubtitleFontSize] = useState(16);
  const [emotionOverlayEnabled, setEmotionOverlayEnabled] = useState(false);
  const [autoCaptureEnabled, setAutoCaptureEnabled] = useState(false);
  const [cameraPermissionEnabled, setCameraPermissionEnabled] = useState(false);
  const [activeStyle, setActiveStyle] = useState(null);
  const [translationStyle, setTranslationStyle] = useState('Casual');
  const [inputLanguage, setInputLanguage] = useState('English');
  const [outputLanguage, setOutputLanguage] = useState('Japanese');
  const [regionalDialect, setRegionalDialect] = useState('Default');
  const [availableLanguages, setAvailableLanguages] = useState([]);
  const [loading, setLoading] = useState(false);

  // Mock user data - in real app, get from auth context
  const userId = 'user123';
  const deviceFingerprint = 'device123';
  const zkpProof = 'proof123';

  useEffect(() => {
    const loadLanguages = async () => {
      setLoading(true);
      try {
        const languages = await fetchLanguages();
        setAvailableLanguages(languages);
      } catch (error) {
        console.error('Failed to load languages:', error);
      } finally {
        setLoading(false);
      }
    };
    loadLanguages();
  }, []);

  const handleLanguageChange = async (language, type) => {
    const languageObj = availableLanguages.find(l => l.name === language);
    const languageCode = languageObj ? languageObj.code : language;

    if (type === 'input') {
      setInputLanguage(language);
    } else {
      setOutputLanguage(language);
    }
    try {
      await updateUserLanguage(userId, languageCode, deviceFingerprint, zkpProof);
      console.log(`Language updated to ${language}`);
    } catch (error) {
      console.error('Failed to update language:', error);
      // Revert on error
      if (type === 'input') {
        setInputLanguage(inputLanguage);
      } else {
        setOutputLanguage(outputLanguage);
      }
    }
  };

  const handleStylePress = (styleName) => {
    setActiveStyle(activeStyle === styleName ? null : styleName);
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Translation Preferences</Text>
      </View>
      <ScrollView style={styles.container} showsVerticalScrollIndicator={false}>
        <Text style={styles.sectionTitle}>Default Language</Text>
        <View style={styles.languageContainer}>
          <View style={styles.languageBox}>
            <Text>Input Language</Text>
            <Dropdown value={inputLanguage} onSelect={(lang) => handleLanguageChange(lang, 'input')} options={availableLanguages.map(l => l.name)} />
          </View>
          <View style={styles.languageBox}>
            <Text>Output Language</Text>
            <Dropdown value={outputLanguage} onSelect={(lang) => handleLanguageChange(lang, 'output')} options={availableLanguages.map(l => l.name)} />
          </View>
        </View>

        <Text style={styles.sectionTitle}>Regional Dialect</Text>
        <View style={styles.row}>
          <Dropdown value={regionalDialect} onSelect={setRegionalDialect} options={['Default', 'Southern', 'Northern']} />
        </View>
        <Text style={styles.hintText}>
          Set your preferred local dialect for accuracy.
        </Text>

        <Text style={styles.sectionTitle}>Translation Style</Text>
        <View style={styles.row}>
          <Dropdown
            value={translationStyle}
            options={['Casual', 'Formal']}
            onSelect={setTranslationStyle}
          />
        </View>
        <View style={styles.buttonGroup}>
          <TouchableOpacity
            style={[
              styles.styleButton,
              activeStyle === 'Polite' && styles.activeStyleButton,
            ]}
            onPress={() => handleStylePress('Polite')}>
            <Text
              style={[
                styles.styleButtonText,
                activeStyle === 'Polite' && styles.activeStyleButtonText,
              ]}>
              Polite
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[
              styles.styleButton,
              activeStyle === 'Concise' && styles.activeStyleButton,
            ]}
            onPress={() => handleStylePress('Concise')}>
            <Text
              style={[
                styles.styleButtonText,
                activeStyle === 'Concise' && styles.activeStyleButtonText,
              ]}>
              Concise
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[
              styles.styleButton,
              activeStyle === 'Simple' && styles.activeStyleButton,
            ]}
            onPress={() => handleStylePress('Simple')}>
            <Text
              style={[
                styles.styleButtonText,
                activeStyle === 'Simple' && styles.activeStyleButtonText,
              ]}>
              Simple
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[
              styles.styleButton,
              activeStyle === 'Direct' && styles.activeStyleButton,
            ]}
            onPress={() => handleStylePress('Direct')}>
            <Text
              style={[
                styles.styleButtonText,
                activeStyle === 'Direct' && styles.activeStyleButtonText,
              ]}>
              Direct
            </Text>
          </TouchableOpacity>
        </View>

        <Text style={styles.sectionTitle}>Subtitle Customization</Text>
        <View style={styles.sliderContainer}>
          <Text>Font Size</Text>
          <Slider
            style={styles.slider}
            minimumValue={10}
            maximumValue={30}
            step={1}
            value={subtitleFontSize}
            onValueChange={value => setSubtitleFontSize(value)}
            minimumTrackTintColor="#FFA364"
            maximumTrackTintColor="#D3D3D3"
            thumbTintColor="#FFA364"
          />
          <Text>{subtitleFontSize}</Text>
        </View>
        <View style={styles.toggleRow}>
          <Text>Emotion Overlay</Text>
          <CustomToggleSwitch
            value={emotionOverlayEnabled}
            onValueChange={setEmotionOverlayEnabled}
          />
        </View>

        <Text style={styles.sectionTitle}>OCR Settings</Text>
        <View style={styles.toggleRow}>
          <Text>Camera Permission</Text>
          <CustomToggleSwitch
            value={cameraPermissionEnabled}
            onValueChange={setCameraPermissionEnabled}
          />
        </View>
        <View style={styles.toggleRow}>
          <Text>Auto-capture</Text>
          <CustomToggleSwitch
            value={autoCaptureEnabled}
            onValueChange={setAutoCaptureEnabled}
          />
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#fff',
  },
  header: {
    paddingTop: 44,
    paddingHorizontal: 20,
    paddingBottom: 4,
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
  },
  backButton: {
    paddingRight: 16,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500', // Corrected to match standard
    color: '#0C0D11', // Corrected to match standard
   
  },
  container: {
    flex: 1,
    paddingHorizontal: 16,
    paddingTop: 16,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: '600',
    marginTop: 20,
    marginBottom: 10,
  },
  languageContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  languageBox: {
    flex: 1,
    marginRight: 10,
  },
  dropdownWrapper: {
    flex: 1,
    marginRight: 10,
    marginBottom: 0,
  },
  dropdownButton: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#4A4A4A',
    borderRadius: 12,
    backgroundColor: '#F6F6F8',
    padding: 12,
    marginTop: 8,
  },
  dropdownButtonOpen: {
    borderBottomLeftRadius: 0,
    borderBottomRightRadius: 0,
  },
  dropdownList: {
    borderWidth: 1,
    borderColor: '#4A4A4A',
    borderTopWidth: 0,
    backgroundColor: '#F6F6F8',
    borderBottomLeftRadius: 12,
    borderBottomRightRadius: 12,
    overflow: 'hidden',
  },
  dropdownOption: {
    padding: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  lastDropdownOption: {
    borderBottomWidth: 0,
  },
  selectedOption: {
    backgroundColor: 'rgba(255, 163, 100, 0.4)',
  },
  row: {
    marginBottom: 10,
  },
  hintText: {
    fontSize: 12,
    color: '#888',
    marginBottom: 5,
  },
  buttonGroup: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  styleButton: {
    borderWidth: 1,
    borderColor: '#2C2C2C',
    borderRadius: 48,
    paddingVertical: 8,
    paddingHorizontal: 16,
  },
  styleButtonText: {
    color: '#000',
  },
  activeStyleButton: {
    backgroundColor: '#FFA364',
    borderWidth: 0,
    borderColor: 'transparent',
  },
  activeStyleButtonText: {
    color: '#000',
  },
  sliderContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  slider: {
    flex: 1,
    marginHorizontal: 10,
  },
  toggleRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 20,
  },
  customSwitchTrack: {
    width: 38.25,
    height: 23.25,
    borderRadius: 75,
    backgroundColor: 'rgba(120, 120, 128, 0.16)',
    justifyContent: 'center',
    overflow: 'visible',
  },
  customSwitchThumb: {
    width: 20.25,
    height: 20.25,
    borderRadius: 75,
    backgroundColor: '#fff',
    ...Platform.select({
      ios: {
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.4,
        shadowRadius: 4,
      },
      android: {
        elevation: 4,
      },
    }),
  },
  navIconsBackContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 36,
    width: 36,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
  },
  vector: {
    position: 'absolute',
    flexShrink: 0,
    top: 12,
    right: 21,
    bottom: 12,
    left: 9,
    overflow: 'visible',
  },
});

export default TranslationPreferencesScreen; 