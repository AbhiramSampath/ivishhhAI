import React, { useState, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  TextInput,
  ScrollView,
  SafeAreaView,
  Image,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { Search, Download, Check, ChevronLeft } from 'lucide-react-native';
import { switchLanguage } from './api/index';


const ALL_LANGUAGES = [
  { code: 'ab', name: 'Abkhaz', isDownloaded: false },
  { code: 'af', name: 'Afrikaans', isDownloaded: false },
  { code: 'sq', name: 'Albanian', isDownloaded: false },
  { code: 'am', name: 'Amharic', isDownloaded: false },
  { code: 'ar', name: 'Arabic', isDownloaded: false },
  { code: 'en', name: 'English', isDownloaded: false },
  { code: 'hi', name: 'Hindi', isDownloaded: false },
  { code: 'te', name: 'Telugu', isDownloaded: false },
];

export default function LanguageScreen() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState(null);
  const [downloadingLanguages, setDownloadingLanguages] = useState(new Set());
  const [recentLanguages, setRecentLanguages] = useState([]);
  const [allLanguages, setAllLanguages] = useState(ALL_LANGUAGES);
  const navigation = useNavigation();

  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) {
      return [];
    }
    const query = searchQuery.toLowerCase();
    const recentResults = recentLanguages.filter(lang =>
      lang.name.toLowerCase().includes(query)
    );
    const allResults = allLanguages.filter(lang =>
      lang.name.toLowerCase().includes(query)
    );
    const combined = [...recentResults, ...allResults];
    const unique = combined.filter((lang, index, self) =>
      index === self.findIndex(l => l.code === lang.code)
    );
    return unique;
  }, [searchQuery, recentLanguages, allLanguages]);

  const filteredAllLanguages = useMemo(() => {
    return allLanguages.filter(
      lang => !recentLanguages.some(recent => recent.code === lang.code)
    );
  }, [allLanguages, recentLanguages]);

  const handleLanguageSelect = async (language) => {
    setSelectedLanguage(language.code);
    setSearchQuery('');
    try {
      const userId = 'dummy_user_token_1234567890';
      const command = `switch to ${language.name}`;
      const result = await switchLanguage(userId, command);
      if (result.status === 'success') {
        Alert.alert('Success', `Language switched to ${language.name}`);
      } else {
        Alert.alert('Error', result.detail || 'Failed to switch language');
      }
    } catch (error) {
      Alert.alert('Error', error.message || 'Failed to switch language');
    }
  };

  const handleDownloadLanguage = async (language) => {
    if (language.isDownloaded || downloadingLanguages.has(language.code)) return;
    setDownloadingLanguages(prev => new Set(prev).add(language.code));
    setTimeout(() => {
      setDownloadingLanguages(prev => {
        const newSet = new Set(prev);
        newSet.delete(language.code);
        return newSet;
      });
      const updatedLanguage = { ...language, isDownloaded: true };
      setRecentLanguages(prev => {
        const isAlreadyRecent = prev.some(recent => recent.code === language.code);
        if (!isAlreadyRecent) {
          return [updatedLanguage, ...prev.slice(0, 4)];
        }
        return prev.map(lang => lang.code === language.code ? updatedLanguage : lang);
      });
      setAllLanguages(prev =>
        prev.map(lang => lang.code === language.code ? updatedLanguage : lang)
      );
      setSearchQuery('');
    }, 2000);
  };

  const handleDetectLanguage = () => {
    const randomLanguage = ALL_LANGUAGES[Math.floor(Math.random() * ALL_LANGUAGES.length)];
    handleLanguageSelect(randomLanguage);
  };

  const handleBackPress = () => {
    navigation.navigate('Translate2');
  };

  const LanguageItem = ({ language, isRecent = false }) => {
    const isDownloading = downloadingLanguages.has(language.code);
    return (
      <TouchableOpacity
        style={[
          styles.languageItem,
          selectedLanguage === language.code && styles.selectedLanguageItem
        ]}
        onPress={() => handleLanguageSelect(language)}
      >
        <Text style={[
          styles.languageName,
          selectedLanguage === language.code && styles.selectedLanguageName
        ]}>
          {language.name}
        </Text>
        <TouchableOpacity
          style={styles.downloadButton}
          onPress={() => handleDownloadLanguage(language)}
          disabled={language.isDownloaded || isDownloading}
        >
          {language.isDownloaded ? (
            <Check size={20} color="#FFFFFF" />
          ) : isDownloading ? (
            <View style={styles.loadingIndicator} />
          ) : (
            <Download size={20} color="#8E8E93" />
          )}
        </TouchableOpacity>
      </TouchableOpacity>
    );
  };

  const isSearching = searchQuery.trim().length > 0;

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={handleBackPress}>
          <ChevronLeft size={24} color="#fff" />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Choose Language</Text>
      </View>
      <View style={styles.searchContainer}>
        <Search size={18} color="#8E8E93" />
        <TextInput
          style={styles.searchInput}
          placeholder="Search Language"
          placeholderTextColor="#8E8E93"
          value={searchQuery}
          onChangeText={setSearchQuery}
        />
      </View>
      {!isSearching && (
        <TouchableOpacity
          style={styles.detectLanguageButton}
          onPress={handleDetectLanguage}
        >
          <Text style={styles.detectLanguageText}>Detect Language</Text>
          <Image
            source={require('./assets/imagecopy.png')}
            style={styles.logoImage}
            resizeMode="contain"
          />
        </TouchableOpacity>
      )}
      <ScrollView style={styles.scrollContainer} showsVerticalScrollIndicator={false}>
        {isSearching && searchResults.length > 0 && (
          <View style={styles.section}>
            {searchResults.map((language) => (
              <LanguageItem
                key={`search-${language.code}`}
                language={language}
              />
            ))}
          </View>
        )}
        {isSearching && searchResults.length === 0 && (
          <View style={styles.noResultsContainer}>
            <Text style={styles.noResultsText}>No languages found</Text>
          </View>
        )}
        {!isSearching && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>Recent</Text>
            {recentLanguages.length === 0 ? (
              <View style={styles.emptyRecentContainer}>
                <Text style={styles.emptyRecentText}>No recent languages</Text>
              </View>
            ) : (
              recentLanguages.map((language) => (
                <LanguageItem
                  key={`recent-${language.code}`}
                  language={language}
                  isRecent={true}
                />
              ))
            )}
          </View>
        )}
        {!isSearching && (
          <View style={styles.section}>
            <Text style={styles.sectionTitle}>All Languages</Text>
            {filteredAllLanguages.map((language) => (
              <LanguageItem
                key={`all-${language.code}`}
                language={language}
              />
            ))}
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#000',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 20,
    paddingTop:50,
  },
  backButton: {
    padding: 5,
    marginRight: 10,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#F6F6F8',
    fontFamily: 'Poppins',
    lineHeight: 26,
  },
  searchContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#1C1C1E',
    marginHorizontal: 20,
    marginVertical: 15,
    paddingHorizontal: 15,
    paddingVertical: 12,
    borderRadius: 12,
    gap: 10,
  },
  searchInput: {
    flex: 1,
    color: '#fff',
    fontSize: 16,
  },
  detectLanguageButton: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#1C1C1E',
    marginHorizontal: 20,
    marginBottom: 20,
    paddingHorizontal: 20,
    paddingVertical: 15,
    borderRadius: 12,
  },
  detectLanguageText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '500',
  },
  logoImage: {
    width: 20,
    height: 20,
  },
  scrollContainer: {
    flex: 1,
  },
  section: {
    marginBottom: 30,
  },
  sectionTitle: {
    color: '#8E8E93',
    fontSize: 14,
    fontWeight: '600',
    textTransform: 'uppercase',
    marginHorizontal: 20,
    marginBottom: 10,
    letterSpacing: 0.5,
  },
  languageItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 15,
    backgroundColor: 'transparent',
  },
  selectedLanguageItem: {
    backgroundColor: '#1C1C1E',
  },
  languageName: {
    color: '#FFFFFF',
    fontSize: 18,
    fontWeight: '500',
    fontFamily: 'Cabinet Grotesk',
    lineHeight: 23.4,
  },
  selectedLanguageName: {
    color: '#007AFF',
    fontWeight: '600',
  },
  downloadButton: {
    padding: 5,
  },
  loadingIndicator: {
    width: 20,
    height: 20,
    borderRadius: 10,
    borderWidth: 2,
    borderColor: '#007AFF',
    borderTopColor: 'transparent',
  },
  noResultsContainer: {
    paddingHorizontal: 20,
    paddingVertical: 40,
    alignItems: 'center',
  },
  noResultsText: {
    color: '#8E8E93',
    fontSize: 16,
  },
  emptyRecentContainer: {
    paddingHorizontal: 20,
    paddingVertical: 20,
    alignItems: 'center',
  },
  emptyRecentText: {
    color: '#8E8E93',
    fontSize: 14,
  },
});