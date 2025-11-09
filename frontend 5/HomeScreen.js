import React from 'react';
import { ScrollView, StyleSheet, StatusBar, View, Alert } from 'react-native';
import { useNavigation } from '@react-navigation/native';
import IntroSection from './IntroSection';
import AvatarCreationCard from './AvatarCreationCard';
import QuickTranslateContainer from './QuickTranslateContainer';
import QuickPhrases from './QuickPhrases';
import Footer from './Footer';
import { updateAvatar } from './api/index';

export default function Homescreen() {
  const navigation = useNavigation();

  const handleAvatarPress = async () => {
    try {
      // Generate a new avatar URL for the user
      const newAvatarUrl = 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=100&h=100&fit=crop&crop=face';

      // Call backend API to update avatar
      const response = await updateAvatar('dummy_user_token_1234567890', newAvatarUrl);

      if (response.success) {
        console.log('Avatar updated successfully:', response);
        // Navigate to avatar creation screen
        navigation.navigate('CreateAvatar');
      } else {
        Alert.alert('Error', `Failed to update avatar: ${response.detail || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Error updating avatar:', error);
      Alert.alert('Error', 'Failed to connect to server. Please try again.');
    }
  };

  return (
    <View style={styles.safeArea}>
      <StatusBar barStyle="light-content" backgroundColor="transparent" translucent={true} />
      <ScrollView 
        style={styles.container} 
        contentContainerStyle={{ paddingBottom: 132 }}
        showsVerticalScrollIndicator={false}
      >
        <IntroSection />
        <AvatarCreationCard onPress={handleAvatarPress} />
        <QuickTranslateContainer />
        <QuickPhrases />
      </ScrollView>
      <Footer />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#000000",
    paddingTo: 16,
    paddingBottom: 16,
    paddingHorizontal: 0,
  },
  safeArea: {
    flex: 1,
  },
});