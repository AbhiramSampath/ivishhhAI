import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import HomeScreen from './HomeScreen';
import CombinedScreen from './ani3';
import CameraScreen from './phrasebook';
import PhrasebookScreen from './phrasebook';
import CreateAvatarScreen from './CreateAvatar';
import TranslationScreen from './Translate2';
import ChooseLanguageIndex from './chooselanguageindex';
import ARTranslate1Screen from './ARtranslate1index.js';
import ChooseLanguageIndexCopy from './chooselanguageindexcopy';
import ChatList from './chatsScreen';
import ChatHeaderScreen from './ChatHeaderScreen';
import SplashOnboarding from './onboarding';
import Voicecall from './Voicecall';
import Profile from './profilepage';
import VoiceSettings from './voicesettings';
import Settings from './settings';
import TranslationPreferencesScreen from './translationalpreferences';
import Legal from './legalinformation';
import Policy from './privacy policy';
import Terms from './terms and condition';
import PrivacySecurity from './privacy security';
import HelpSupport from './help and feedback';
import FAQ from './faq';
import Feedback from './feedback';
import AccountDetails from './accoundetails_integrated'; // Updated to use integrated version
import LinkedAccounts from './linkedaccounts';
import ChangePassword from './chnage password';
import BlockchainScreen from './Blockchain.js';
import VoiceBiometrics from './VoiceBiometrics';
import Opensource from './Opensource';
import Personalisation from './Personalization';

const Stack = createNativeStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator
        initialRouteName="Splash"
        screenOptions={{
          headerShown: false,
          animation: 'none',
          gestureEnabled: true,
          gestureDirection: 'horizontal',
        }}
      >
        <Stack.Screen name="Splash" component={CombinedScreen} />
        <Stack.Screen name="Onboarding" component={SplashOnboarding} />
        <Stack.Screen name="Home" component={HomeScreen} />
        <Stack.Screen name="ChatList" component={ChatList} />
        <Stack.Screen name="ChatHeaderScreen" component={ChatHeaderScreen} />
        <Stack.Screen name="Camera" component={CameraScreen} />
        <Stack.Screen name="Phrasebook" component={PhrasebookScreen} />
        <Stack.Screen name="CreateAvatar" component={CreateAvatarScreen} />
        <Stack.Screen name="Translate2" component={TranslationScreen} />
        <Stack.Screen name="ChooseLanguageIndex" component={ChooseLanguageIndex} />
        <Stack.Screen name="ARTranslate1" component={ARTranslate1Screen} />
        <Stack.Screen name="ChooseLanguageIndexCopy" component={ChooseLanguageIndexCopy} />
        <Stack.Screen name="Voicecall" component={Voicecall} />
        <Stack.Screen name="Profile" component={Profile} />
        <Stack.Screen name="VoiceSettings" component={VoiceSettings} />
        <Stack.Screen name="Settings" component={Settings} />
        <Stack.Screen name="TranslationPreferences" component={TranslationPreferencesScreen} />
        <Stack.Screen name="LegalInformation" component={Legal} />
        <Stack.Screen name="PrivacyPolicy" component={Policy} />
        <Stack.Screen name="TermsConditions" component={Terms} />
        <Stack.Screen name="PrivacySecurity" component={PrivacySecurity} />
        <Stack.Screen name="HelpAndFeedback" component={HelpSupport} />
        <Stack.Screen name="Faq" component={FAQ} />
        <Stack.Screen name="Feedback" component={Feedback} />
        <Stack.Screen name="AccountDetails" component={AccountDetails} />
        <Stack.Screen name="LinkedAccounts" component={LinkedAccounts} />
        <Stack.Screen name="ChangePassword" component={ChangePassword} />
        <Stack.Screen name="Blockchain" component={BlockchainScreen} />
        <Stack.Screen name="VoiceBiometrics" component={VoiceBiometrics} />
        <Stack.Screen name="Opensource" component={Opensource} />
        <Stack.Screen name="Personalisation" component={Personalisation} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
