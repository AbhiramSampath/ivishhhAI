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
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { 
  ArrowLeft, 
  Volume2, 
  Star, 
  Users, 
  Mic
} from 'lucide-react-native';
import { Svg, Path } from 'react-native-svg';

const PRIMARY_PERANO = '#F9FFA2';

export default function TranslationScreen() {
  const [inputText, setInputText] = useState('');
  const [translatedText, setTranslatedText] = useState('पाठ यहाँ लिखें');
  const [isStarred, setIsStarred] = useState(false);
  const navigation = useNavigation();

  const translateText = (text) => {
    // Simple mock translation - in real app you'd call translation API
    if (text.toLowerCase().includes('hello')) {
      setTranslatedText('नमस्ते');
    } else if (text.toLowerCase().includes('how are you')) {
      setTranslatedText('आप कैसे हैं?');
    } else if (text) {
      setTranslatedText('पाठ यहाँ लिखें');
    } else {
      setTranslatedText('पाठ यहाँ लिखें');
    }
  };

  const handleMicPress = () => {
    navigation.navigate('Translate2');
  };

  const handleBackPress = () => {
    navigation.navigate('Home');
  };

  const handleStarPress = () => {
    setIsStarred(!isStarred);
  };

  const handleLanguagePress = () => {
    navigation.navigate('ChooseLanguageIndex');
  };

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: PRIMARY_PERANO }]}>
      <StatusBar barStyle="dark-content" backgroundColor={PRIMARY_PERANO} />
      
      {/* Header */}
      <View style={[styles.header, { backgroundColor: PRIMARY_PERANO }]}> 
        <TouchableOpacity style={styles.backButton} onPress={handleBackPress}>
          <ArrowLeft size={24} color="#000" />
          <Text style={styles.backButtonText}>Back</Text>
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
          <TouchableOpacity style={styles.starButton} onPress={handleStarPress}>
            {isStarred ? (
              <View style={styles.phraseStarContainer}>
                <View style={styles.bxsstarsvg}>
                  <Svg style={styles.vector} width="20" height="20" viewBox="0 0 20 20" fill="none">
                    <Path d="M19.947 7.17901C19.8842 6.99388 19.7685 6.83121 19.6142 6.71107C19.46 6.59094 19.2739 6.51861 19.079 6.50301L13.378 6.05001L10.911 0.589014C10.8325 0.413127 10.7047 0.263736 10.5431 0.158872C10.3815 0.0540081 10.193 -0.00184725 10.0004 -0.00195297C9.80771 -0.0020587 9.61916 0.0535897 9.45745 0.158276C9.29574 0.262963 9.16779 0.412213 9.08903 0.588015L6.62203 6.05001L0.921026 6.50301C0.729482 6.51819 0.546364 6.58822 0.393581 6.70475C0.240798 6.82127 0.124819 6.97934 0.0595194 7.16004C-0.00578038 7.34075 -0.0176359 7.53645 0.0253712 7.72372C0.0683784 7.91099 0.164427 8.0819 0.302026 8.21601L4.51503 12.323L3.02503 18.775C2.97978 18.9703 2.99428 19.1747 3.06665 19.3617C3.13901 19.5486 3.26589 19.7095 3.43083 19.8235C3.59577 19.9374 3.79115 19.9991 3.99161 20.0007C4.19208 20.0022 4.38837 19.9434 4.55503 19.832L10 16.202L15.445 19.832C15.6154 19.9451 15.8162 20.0033 16.0207 19.9988C16.2251 19.9944 16.4232 19.9274 16.5884 19.8069C16.7536 19.6865 16.878 19.5183 16.9448 19.3251C17.0116 19.1318 17.0176 18.9228 16.962 18.726L15.133 12.326L19.669 8.24401C19.966 7.97601 20.075 7.55801 19.947 7.17901Z" fill="#787878"/>
                  </Svg>
                </View>
              </View>
            ) : (
              <Star size={24} color="#666" />
            )}
          </TouchableOpacity>
        </View>
        
        <View style={styles.translatedTextContainer}>
          <Text style={styles.translatedText}>{translatedText}</Text>
        </View>
      </View>

      {/* Footer */}
      <View style={styles.footer}>
        <View style={styles.actionButtons}>
          <TouchableOpacity style={styles.actionButton}>
            <Users size={22} color="#fff" />
          </TouchableOpacity>
          
          <TouchableOpacity style={[styles.actionButton, styles.micButton]} onPress={handleMicPress}>
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
          <TouchableOpacity style={styles.languageBox} onPress={handleLanguagePress}>
            <Text style={styles.languageText}>Hindi</Text>
          </TouchableOpacity>
          <Image
            source={require('./assets/swap.png')}
            style={styles.translationArrowLogo}
            resizeMode="contain"
          />
          <TouchableOpacity style={styles.languageBox} onPress={handleLanguagePress}>
            <Text style={styles.languageText}>English</Text>
          </TouchableOpacity>
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
    marginLeft: 0,
    marginTop: 32,
    justifyContent: 'flex-start',
    alignItems: 'center',
    backgroundColor: 'transparent',
    flexDirection: 'row',
  },
  backButtonText: {
    color: '#000',
    fontFamily: 'Cabinet Grotesk',
    fontSize: 16,
    fontWeight: '500',
    lineHeight: 26,
    textAlign: 'left',
    marginLeft: 10,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: 8,
  },
  headerTitle: {
    color: '#4A4A4A',
    fontFamily: 'Cabinet Grotesk',
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
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
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
    backgroundColor: '#FFA364',
    width: 65, 
    height: 65,
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
    fontFamily: 'Cabinet Grotesk',
    fontSize: 20,
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
  phraseStarContainer: {
    width: 24,
    height: 24,
    justifyContent: 'center',
    alignItems: 'center',
  },
  bxsstarsvg: {
    width: '100%',
    height: '100%',
    justifyContent: 'center',
    alignItems: 'center',
  },
  vector: {
    width: '100%',
    height: '100%',
  },
});