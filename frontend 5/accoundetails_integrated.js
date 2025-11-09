import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  Animated,
  Image,
  Alert,
} from 'react-native';
import { useNavigation } from '@react-navigation/native';
import { Svg, Path } from 'react-native-svg';
import { getUserDetails, updateVoiceAuth } from './api/index';

// Component for the new back arrow
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="#2C2C2C" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

// Component for the right-facing arrow (unchanged)
function IconlyLightArrowRight() {
  return (
    <View style={styles.iconlyLightArrowRightContainer}>
      <Svg width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M1.04004 13L7.04004 7L1.04004 1" stroke="black" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

// Component for the custom toggle switch with animation
function Toggle({ isEnabled, onToggle }) {
  const animatedValue = useRef(new Animated.Value(isEnabled ? 17 : 2)).current;

  useEffect(() => {
    Animated.timing(animatedValue, {
      toValue: isEnabled ? 17 : 2,
      duration: 200,
      useNativeDriver: false,
    }).start();
  }, [isEnabled, animatedValue]);

  return (
    <TouchableOpacity onPress={onToggle}>
      <View style={[styles.toggleContainer, isEnabled && styles.toggleOn]}>
        <Animated.View style={[styles.knob, { left: animatedValue }]} />
      </View>
    </TouchableOpacity>
  );
}

export default function AccountDetails() {
  const [voiceAuthEnabled, setVoiceAuthEnabled] = useState(false);
  const [userDetails, setUserDetails] = useState({ name: '', email: '', profileImage: '' });
  const [loading, setLoading] = useState(true);
  const navigation = useNavigation();

  useEffect(() => {
    fetchUserDetails();
  }, []);

  const fetchUserDetails = async () => {
    try {
      // Assuming user ID is available, e.g., from auth context or props
      const userId = 'current_user_id'; // Replace with actual user ID
      const data = await getUserDetails(userId);
      setUserDetails({
        name: data.name || 'User',
        email: data.email || '',
        profileImage: data.profile_image || 'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=100&h=100&fit=crop&crop=face',
      });
      setVoiceAuthEnabled(data.voice_auth_enabled || false);
    } catch (error) {
      console.error('Error fetching user details:', error);
      Alert.alert('Error', 'Failed to load user details');
    } finally {
      setLoading(false);
    }
  };

  const handleVoiceAuthToggle = async () => {
    const newState = !voiceAuthEnabled;
    try {
      const userId = 'current_user_id'; // Replace with actual user ID
      await updateVoiceAuth(userId, newState);
      setVoiceAuthEnabled(newState);
    } catch (error) {
      console.error('Error updating voice auth:', error);
      Alert.alert('Error', 'Failed to update voice authentication setting');
    }
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Account Details</Text>
      </View>

      {/* Profile Section */}
      <View style={styles.profileSection}>
        <View style={styles.profileInfo}>
          <Image
            source={{ uri: userDetails.profileImage }}
            style={styles.profileImage}
          />
          <View style={styles.userInfo}>
            <Text style={styles.userName}>{userDetails.name}</Text>
            <Text style={styles.userEmail}>{userDetails.email}</Text>
          </View>
        </View>
        <TouchableOpacity style={styles.editButton}>
          <Text style={styles.editButtonText}>Edit</Text>
        </TouchableOpacity>
      </View>

      {/* Menu Items */}
      <View style={styles.menuContainer}>
        <TouchableOpacity style={styles.menuItem} onPress={() => navigation.navigate('LinkedAccounts')}>
          <Text style={styles.menuItemText}>Linked Accounts</Text>
          <IconlyLightArrowRight />
        </TouchableOpacity>

        <TouchableOpacity style={styles.menuItem} onPress={() => navigation.navigate('ChangePassword')}>
          <Text style={styles.menuItemText}>Change Password</Text>
          <IconlyLightArrowRight />
        </TouchableOpacity>
      </View>

      {/* Voice Authentication Section */}
      <View style={styles.voiceAuthContainer}>
        <View style={styles.voiceAuthHeader}>
          <Text style={styles.voiceAuthTitle}>Voice Authentication</Text>
          <Toggle
            isEnabled={voiceAuthEnabled}
            onToggle={handleVoiceAuthToggle}
          />
        </View>
        <Text style={styles.voiceAuthDescription}>
          Use your voice to securely access your account.
        </Text>
        <TouchableOpacity
          style={styles.reEnrollButton}
        >
          <Text style={styles.reEnrollButtonText}>Re-enroll</Text>
        </TouchableOpacity>
      </View>

      {/* Bottom Decorative Element */}
      <View style={styles.bottomDecoration} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',

    fontSize: 20,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    columnGap: 8,
    paddingTop: 44,
    paddingHorizontal: 20,
    paddingBottom: 4,
   paddingRight:20,
  },
  backButton: {

    fontSize: 20,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#0C0D11',
  },
  placeholder: {
    width: 18,
  },
  profileSection: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 20,
  },
  profileInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  profileImage: {
    width: 60,
    height: 60,
    borderRadius: 30,
    marginRight: 15,
  },
  userInfo: {
    flex: 1,
  },
  userName: {
    fontSize: 20,
    fontWeight: '600',
    color: '#000',
    marginBottom: 2,
  },
  userEmail: {
    fontSize: 14,
    color: '#666',
  },
  editButton: {
    backgroundColor: '#F6F6F8',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 12,
  },
  editButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#2C2C2C',
    lineHeight: 27,
  },
  menuContainer: {
    paddingHorizontal: 20,
    marginTop: 10,
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 20,
  },
  menuItemText: {
    fontSize: 16,
    color: '#000',
  },
  voiceAuthContainer: {
    paddingHorizontal: 20,
    marginTop: 20,
  },
  voiceAuthHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 8,
  },
  voiceAuthTitle: {
    fontSize: 16,
    color: '#000',
  },
  voiceAuthDescription: {
    fontSize: 12,
    color: '#666',
    marginBottom: 15,
    lineHeight: 16,
  },
  reEnrollButton: {
    alignSelf: 'flex-end',
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    paddingTop: 8,
    paddingBottom: 8,
    backgroundColor: '#F2F2F7',
  },
  reEnrollButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#000',
    paddingTop: 6,
    paddingBottom: 6,
  },
  bottomDecoration: {
    position: 'absolute',
    bottom: -50,
    right: -100,
    width: 200,
    height: 200,
    borderRadius: 100,
    borderWidth: 2,
    borderColor: '#E5E5EA',
    opacity: 0.3,
  },
  // New styles for the imported components
  iconlyLightArrowRightContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 8,
    width: 48,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
    fontSize: 20,
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
  // Styles for the custom toggle switch
  toggleContainer: {
    position: 'relative',
    flexShrink: 0,
    height: 23,
    width: 38,
    backgroundColor: 'rgba(120, 120, 128, 0.16)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    rowGap: 0,
    borderRadius: 75,
    justifyContent: 'center',
    marginRight: 20,
  },
  knob: {
    position: 'absolute',
    flexShrink: 0,
    top: 2,
    bottom: 2,
    width: 19,
    backgroundColor: 'rgba(255, 255, 255, 1)',
    shadowColor: 'rgba(0, 0, 0, 0.06)',
    shadowOffset: {
      width: 0,
      height: 2.25,
    },
    shadowRadius: 0.75,
    borderRadius: 75,
  },
  toggleOn: {
    backgroundColor: '#FFA364',
  },
});
