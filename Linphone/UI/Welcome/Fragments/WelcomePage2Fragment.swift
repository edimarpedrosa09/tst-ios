/*
 * Copyright (c) 2010-2023 Belledonne Communications SARL.
 *
 * This file is part of Linphone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

import Foundation
import SwiftUI

struct WelcomePage2Fragment: View {
	
	var body: some View {
		VStack {
			Spacer()
			VStack {
				Image("secured")
					.renderingMode(.template)
					.resizable()
					.foregroundStyle(Color.orangeMain500)
					.frame(width: 70, height: 100)
				Text("welcome_page_2_title")
					.welcome_text_style_gray_800(styleSize: 30)
					.padding(.bottom, 20)
				Text("welcome_page_2_message")
					.welcome_text_style_gray(styleSize: 15)
					.multilineTextAlignment(.center)
				
			}
			Spacer()
			Spacer()
		}
		.frame(maxWidth: .infinity)
	}
}

#Preview {
	WelcomePage2Fragment()
}