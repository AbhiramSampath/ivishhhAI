import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  TextInput,
  Alert,
} from 'react-native';
import { Svg, Path, Circle } from 'react-native-svg';
import { useNavigation } from '@react-navigation/native';
import { changePassword } from './api/index';

// Component for the new back arrow
function NavIconsBack() {
  return (
    <View style={styles.navIconsBackContainer}>
      <Svg style={styles.vector} width="8" height="14" viewBox="0 0 8 14" fill="none">
        <Path d="M7 1L1 7L7 13" stroke="black" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
      </Svg>
    </View>
  );
}

export default function ChangePassword() {
  const navigation = useNavigation();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isPasswordUpdated, setIsPasswordUpdated] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSave = async () => {
    if (!currentPassword || !newPassword || !confirmPassword) {
      Alert.alert('Error', 'Please fill in all fields');
      return;
    }
    if (newPassword !== confirmPassword) {
      Alert.alert('Error', 'New passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      Alert.alert('Error', 'New password must be at least 8 characters');
      return;
    }
    setLoading(true);
    try {
      const userId = 'dummy_user_token_1234567890';
      const result = await changePassword(userId, currentPassword, newPassword);
      if (result.success) {
        setIsPasswordUpdated(true);
      } else {
        Alert.alert('Error', result.message || 'Failed to change password');
      }
    } catch (error) {
      Alert.alert('Error', error.message || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const handleDone = () => {
    // Navigate back or close modal
    setIsPasswordUpdated(false);
    navigation.goBack(); // Navigate back to the previous screen
  };

  if (isPasswordUpdated) {
    return (
      <View style={styles.container}>
        {/* Success Content */}
        <View style={styles.successContentWrapper}>
          <View style={styles.checkmarkContainer}>
            <Svg width={60} height={60} viewBox="0 0 24 24" fill="none">
              <Path
                d="M9 12l2 2 4-4"
                stroke="#fff"
                strokeWidth={2.5}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </Svg>
          </View>

          <Text style={styles.successTitle}>
            Your Password has been Updated
          </Text>

          <TouchableOpacity style={styles.doneButton} onPress={handleDone}>
            <Text style={styles.doneButtonText}>Done</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <TouchableOpacity style={styles.backButton} onPress={() => navigation.goBack()}>
          <NavIconsBack />
        </TouchableOpacity>
        <Text style={styles.headerTitle}>Change Password</Text>
        <View style={styles.placeholder} />
      </View>

      {/* Form */}
      <View style={styles.formContainer}>
        {/* Current Password */}
        <View style={styles.inputContainer}>
          <TextInput
            style={styles.textInput}
            placeholder="Current Password"
            placeholderTextColor="#999"
            value={currentPassword}
            onChangeText={setCurrentPassword}
            secureTextEntry={!showCurrentPassword}
          />
          <TouchableOpacity
            style={styles.eyeButton}
            onPress={() =>
              setShowCurrentPassword(!showCurrentPassword)
            }
          >
            <Svg width={20} height={20} viewBox="0 0 24 24" fill="none">
              <Path
                d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"
                stroke="#999"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <Circle
                cx={12}
                cy={12}
                r={3}
                stroke="#999"
                strokeWidth={2}
              />
              {!showCurrentPassword && (
                <Path
                  d="M1 1l22 22"
                  stroke="#999"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
            </Svg>
          </TouchableOpacity>
        </View>

        {/* New Password */}
        <View style={styles.inputContainer}>
          <TextInput
            style={styles.textInput}
            placeholder="New password"
            placeholderTextColor="#999"
            value={newPassword}
            onChangeText={setNewPassword}
            secureTextEntry={!showNewPassword}
          />
          <TouchableOpacity
            style={styles.eyeButton}
            onPress={() => setShowNewPassword(!showNewPassword)}
          >
            <Svg width={20} height={20} viewBox="0 0 24 24" fill="none">
              <Path
                d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"
                stroke="#999"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <Circle
                cx={12}
                cy={12}
                r={3}
                stroke="#999"
                strokeWidth={2}
              />
              {!showNewPassword && (
                <Path
                  d="M1 1l22 22"
                  stroke="#999"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
            </Svg>
          </TouchableOpacity>
        </View>

        {/* Re-enter New Password */}
        <View style={styles.inputContainer}>
          <TextInput
            style={styles.textInput}
            placeholder="Re-enter new password"
            placeholderTextColor="#999"
            value={confirmPassword}
            onChangeText={setConfirmPassword}
            secureTextEntry={!showConfirmPassword}
          />
          <TouchableOpacity
            style={styles.eyeButton}
            onPress={() =>
              setShowConfirmPassword(!showConfirmPassword)
            }
          >
            <Svg width={20} height={20} viewBox="0 0 24 24" fill="none">
              <Path
                d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"
                stroke="#999"
                strokeWidth={2}
                strokeLinecap="round"
                strokeLinejoin="round"
              />
              <Circle
                cx={12}
                cy={12}
                r={3}
                stroke="#999"
                strokeWidth={2}
              />
              {!showConfirmPassword && (
                <Path
                  d="M1 1l22 22"
                  stroke="#999"
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              )}
            </Svg>
          </TouchableOpacity>
        </View>

        {/* Save Button */}
        <TouchableOpacity style={styles.saveButton} onPress={handleSave}>
          <Text style={styles.saveButtonText}>Save</Text>
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
    paddingTop: 30,
   
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 15,
    marginBottom: 30,
    marginRight:210,
  },
  backButton: {
    padding: 5,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '500',
    color: '#000',
  },
  placeholder: {
    width: 18,
  },
  formContainer: {
    paddingHorizontal: 20,
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#F8F8F8',
    borderRadius: 12,
    marginBottom: 16,
    paddingHorizontal: 16,
    height: 56,
  },
  textInput: {
    flex: 1,
    fontSize: 16,
    color: '#000',
  },
  eyeButton: {
    padding: 8,
  },
  saveButton: {
    backgroundColor: '#000',
    paddingVertical: 16,
    borderRadius: 12,
    alignItems: 'center',
    marginTop: 20,
  },
  saveButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  successContentWrapper: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'space-between', // Distribute space between elements
    paddingHorizontal: 40,
    paddingVertical: 80, // Add vertical padding to ensure elements aren't too close to edges
  },
  checkmarkContainer: {
    width: 80, // Increased width
    height: 80, // Increased height
    backgroundColor: '#FFA364',
    borderRadius: 60, // Adjusted to maintain circle shape
    alignItems: 'center',
    justifyContent: 'center',
    marginTop: 60, // Move it up to match the image
    marginBottom: 0,
  },
  successTitle: {
    fontSize: 38, // Increased font size
    fontWeight: '700',
    color: '#000',
    textAlign: 'center',
    marginTop: 60, // Add more space below the checkmark
    lineHeight: 36, // Adjust line height for better readability
  },
  doneButton: {
    backgroundColor: '#000',
    paddingVertical: 17,
    borderRadius: 12,
    width: '100%',
    alignItems: 'center',
    marginBottom: -15, // Remove absolute positioning
    marginTop: 'auto', // Push it to the bottom
  },
  doneButtonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: '600',
  },
  bottomDecoration: {
    // Removed from success screen as per image
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
  // Styles for NavIconsBack component
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